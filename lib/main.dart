import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:camera/camera.dart';
import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:image/image.dart' as img;
import 'package:local_auth/local_auth.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:io';

late final List<CameraDescription> appCameras;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
  ]);

  appCameras = await availableCameras();
  runApp(const VaultCameraApp());
}

class VaultCameraApp extends StatelessWidget {
  const VaultCameraApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Vault Camera',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorSchemeSeed: Colors.indigo,
      ),
      home: const UnlockScreen(),
    );
  }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

class SecureAuth {
  final LocalAuthentication auth = LocalAuthentication();

  Future<bool> authenticate() async {
    try {
      if (!await auth.isDeviceSupported()) return false;
      return await auth.authenticate(
        localizedReason: 'Authenticate to unlock Vault Camera',
        options: const AuthenticationOptions(
          biometricOnly: false,
          sensitiveTransaction: true,
          useErrorDialogs: true,
          stickyAuth: true,
        ),
      );
    } catch (_) {
      return false;
    }
  }
}

class KeyManager {
  static const keyName = 'vault.master.v2';

  final SecureAuth auth;
  final FlutterSecureStorage storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(resetOnError: true),
  );

  KeyManager(this.auth);

  Future<Uint8List?> unlock() async {
    if (!await auth.authenticate()) return null;

    final existing = await storage.read(key: keyName);
    if (existing != null) {
      final bytes = base64Url.decode(existing);
      if (bytes.length != 32) {
        await storage.delete(key: keyName);
        throw StateError('Invalid master key.');
      }
      return Uint8List.fromList(bytes);
    }

    final key = Uint8List.fromList(
      List<int>.generate(
        32,
        (_) => Random.secure().nextInt(256),
      ),
    );

    await storage.write(
      key: keyName,
      value: base64UrlEncode(key),
    );

    return key;
  }
}

// ---------------------------------------------------------------------------
// Vault format
//
// Magic: "VLT01" (5)
// Version: 1 byte
// Algorithm: 1 byte (1 = AES-256-CBC + HMAC-SHA256)
// IV length: 1 byte
// IV: 16
// Ciphertext: variable
// HMAC: 32
//
// HMAC covers header + ciphertext.
// The same 32-byte master key is used by the requested encrypt package.
// For a future native cryptographic backend, derive independent ENC/MAC keys
// with HKDF and keep the file version so migration remains possible.
// ---------------------------------------------------------------------------

class VaultCrypto {
  static const magic = [0x56, 0x4c, 0x54, 0x30, 0x32]; // VLT02
  static const version = 2;
  static const algorithm = 2; // AES-256-GCM
  static const nonceLength = 12;
  static const tagLength = 16;

  final cryptography.AesGcm _aes =
      cryptography.AesGcm.with256bits();

  Future<Uint8List> encrypt(
    Uint8List plaintext,
    Uint8List rawKey,
  ) async {
    final secretKey = cryptography.SecretKey(rawKey);
    final nonce = _aes.newNonce();

    final aad = Uint8List.fromList([
      ...magic,
      version,
      algorithm,
      nonceLength,
    ]);

    final box = await _aes.encrypt(
      plaintext,
      secretKey: secretKey,
      nonce: nonce,
      aad: aad,
    );

    return Uint8List.fromList(
      BytesBuilder(copy: false)
        ..add(aad)
        ..add(box.nonce)
        ..add(box.cipherText)
        ..add(box.mac.bytes)
        .toBytes(),
    );
  }

  Future<Uint8List> decrypt(
    Uint8List payload,
    Uint8List rawKey,
  ) async {
    const minimum = 8 + nonceLength + tagLength + 1;
    if (payload.length < minimum) {
      throw const FormatException('Vault payload too small.');
    }

    for (var i = 0; i < magic.length; i++) {
      if (payload[i] != magic[i]) {
        throw const FormatException('Invalid vault magic.');
      }
    }

    if (payload[5] != version ||
        payload[6] != algorithm ||
        payload[7] != nonceLength) {
      throw const FormatException('Unsupported vault format.');
    }

    final headerLength = 8;
    final cipherEnd = payload.length - tagLength;
    if (cipherEnd <= headerLength + nonceLength) {
      throw const FormatException('Invalid ciphertext.');
    }

    final aad = payload.sublist(0, headerLength);
    final nonce = payload.sublist(
      headerLength,
      headerLength + nonceLength,
    );
    final ciphertext = payload.sublist(
      headerLength + nonceLength,
      cipherEnd,
    );
    final tag = payload.sublist(cipherEnd);

    try {
      final box = cryptography.SecretBox(
        ciphertext,
        nonce: nonce,
        mac: cryptography.Mac(tag),
      );

      return Uint8List.fromList(
        await _aes.decrypt(
          box,
          secretKey: cryptography.SecretKey(rawKey),
          aad: aad,
        ),
      );
    } on cryptography.SecretBoxAuthenticationError {
      throw const FormatException('Authentication failed.');
    }
  }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

class VaultItem {
  final String id;
  final File file;
  final DateTime createdAt;

  const VaultItem({
    required this.id,
    required this.file,
    required this.createdAt,
  });
}

class VaultStorage {
  Future<Directory> directory() async {
    final base = await getApplicationDocumentsDirectory();
    final dir = Directory('${base.path}/vault');
    if (!await dir.exists()) await dir.create(recursive: true);
    return dir;
  }

  Future<void> save(String id, Uint8List payload, DateTime created) async {
    final dir = await directory();
    final file = File('${dir.path}/$id.vault');
    final meta = File('${dir.path}/$id.meta');

    await file.writeAsBytes(payload, flush: true);
    await meta.writeAsString(
      jsonEncode({
        'version': 1,
        'createdAt': created.toUtc().toIso8601String(),
      }),
      flush: true,
    );
  }

  Future<List<VaultItem>> list() async {
    final dir = await directory();
    final result = <VaultItem>[];

    await for (final e in dir.list()) {
      if (e is! File || !e.path.endsWith('.vault')) continue;
      final id = e.uri.pathSegments.last.replaceFirst('.vault', '');
      final meta = File('${dir.path}/$id.meta');
      if (!await meta.exists()) continue;

      try {
        final m = jsonDecode(await meta.readAsString());
        result.add(VaultItem(
          id: id,
          file: e,
          createdAt: DateTime.parse(m['createdAt'] as String),
        ));
      } catch (_) {}
    }

    result.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return result;
  }

  Future<Uint8List> read(VaultItem item) async {
    return Uint8List.fromList(await item.file.readAsBytes());
  }

  Future<void> delete(VaultItem item) async {
    final meta = File(item.file.path.replaceFirst('.vault', '.meta'));
    if (await item.file.exists()) await item.file.delete();
    if (await meta.exists()) await meta.delete();
  }
}

// ---------------------------------------------------------------------------
// Camera memory pipeline
// ---------------------------------------------------------------------------

class MemoryCameraEncoder {
  static Uint8List yuv420ToJpeg(CameraImage image, {int quality = 90}) {
    if (image.format.group != ImageFormatGroup.yuv420) {
      throw UnsupportedError(
        'This strict memory pipeline expects YUV420.',
      );
    }

    final width = image.width;
    final height = image.height;
    final out = img.Image(width: width, height: height);

    final yPlane = image.planes[0];
    final uPlane = image.planes[1];
    final vPlane = image.planes[2];

    final yBytes = yPlane.bytes;
    final uBytes = uPlane.bytes;
    final vBytes = vPlane.bytes;

    final yRowStride = yPlane.bytesPerRow;
    final uRowStride = uPlane.bytesPerRow;
    final vRowStride = vPlane.bytesPerRow;
    final uPixelStride = uPlane.bytesPerPixel ?? 1;
    final vPixelStride = vPlane.bytesPerPixel ?? 1;

    for (var y = 0; y < height; y++) {
      for (var x = 0; x < width; x++) {
        final yValue = yBytes[y * yRowStride + x];

        final uvX = x ~/ 2;
        final uvY = y ~/ 2;

        final uIndex = uvY * uRowStride + uvX * uPixelStride;
        final vIndex = uvY * vRowStride + uvX * vPixelStride;

        final u = uBytes[uIndex];
        final v = vBytes[vIndex];

        final r = (yValue + 1.402 * (v - 128)).round().clamp(0, 255);
        final g = (yValue - 0.344136 * (u - 128) -
                0.714136 * (v - 128))
            .round()
            .clamp(0, 255);
        final b = (yValue + 1.772 * (u - 128)).round().clamp(0, 255);

        out.setPixelRgb(x, y, r, g, b);
      }
    }

    return Uint8List.fromList(img.encodeJpg(out, quality: quality));
  }
}

// ---------------------------------------------------------------------------
// Vault controller
// ---------------------------------------------------------------------------

class VaultController {
  final KeyManager keyManager;
  final VaultCrypto crypto;
  final VaultStorage storage;

  Uint8List? _key;

  VaultController(this.keyManager, this.crypto, this.storage);

  bool get unlocked => _key != null;

  Future<bool> unlock() async {
    _key = await keyManager.unlock();
    return _key != null;
  }

  void lock() {
    _key = null;
  }

  Future<void> store(Uint8List jpegBytes) async {
    final key = _key;
    if (key == null) throw StateError('Vault locked.');

    final payload = await crypto.encrypt(jpegBytes, key);
    final random = Random.secure();
    final id = List<int>.generate(16, (_) => random.nextInt(256))
        .map((e) => e.toRadixString(16).padLeft(2, '0'))
        .join();

    await storage.save(id, payload, DateTime.now().toUtc());
  }

  Future<Uint8List> decrypt(VaultItem item) async {
    final key = _key;
    if (key == null) throw StateError('Vault locked.');
    return crypto.decrypt(await storage.read(item), key);
  }
}

// ---------------------------------------------------------------------------
// Unlock screen
// ---------------------------------------------------------------------------

class UnlockScreen extends StatefulWidget {
  const UnlockScreen({super.key});

  @override
  State<UnlockScreen> createState() => _UnlockScreenState();
}

class _UnlockScreenState extends State<UnlockScreen> {
  late final VaultController vault;
  bool busy = false;

  @override
  void initState() {
    super.initState();
    final auth = SecureAuth();
    vault = VaultController(
      KeyManager(auth),
      VaultCrypto(),
      VaultStorage(),
    );
  }

  Future<void> unlock() async {
    if (busy) return;
    setState(() => busy = true);

    final ok = await vault.unlock();

    if (!mounted) return;
    setState(() => busy = false);

    if (!ok) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Authentication failed.')),
      );
      return;
    }

    Navigator.of(context).pushReplacement(
      MaterialPageRoute(
        builder: (_) => CameraScreen(vault: vault),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.shield, size: 96),
            const SizedBox(height: 24),
            const Text(
              'Vault Camera',
              style: TextStyle(fontSize: 30, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 12),
            const Text('Memory-first encrypted photography'),
            const SizedBox(height: 36),
            FilledButton.icon(
              onPressed: busy ? null : unlock,
              icon: const Icon(Icons.fingerprint),
              label: const Text('Unlock'),
            ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Camera
// ---------------------------------------------------------------------------

class CameraScreen extends StatefulWidget {
  final VaultController vault;

  const CameraScreen({super.key, required this.vault});

  @override
  State<CameraScreen> createState() => _CameraScreenState();
}

class _CameraScreenState extends State<CameraScreen>
    with WidgetsBindingObserver {
  CameraController? controller;
  bool streaming = false;
  bool processing = false;
  bool switching = false;
  int cameraIndex = 0;
  DateTime lastCapture = DateTime.fromMillisecondsSinceEpoch(0);

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initCamera();
  }

  Future<void> _initCamera() async {
    if (appCameras.isEmpty) return;

    controller?.dispose();

    final c = CameraController(
      appCameras[cameraIndex],
      ResolutionPreset.high,
      enableAudio: false,
      imageFormatGroup: ImageFormatGroup.yuv420,
    );

    controller = c;

    try {
      await c.initialize();
      await c.setFlashMode(FlashMode.off);

      if (mounted) setState(() {});
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Camera error: $e')),
        );
      }
    }
  }

  Future<void> capture() async {
    final c = controller;
    if (c == null ||
        !c.value.isInitialized ||
        processing ||
        streaming) {
      return;
    }

    setState(() => streaming = true);

    try {
      await c.startImageStream((frame) {
        if (processing) return;

        final now = DateTime.now();
        if (now.difference(lastCapture) <
            const Duration(milliseconds: 350)) {
          return;
        }

        processing = true;
        lastCapture = now;

        _processFrame(frame);
      });
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Capture stream failed: $e')),
        );
      }
      setState(() => streaming = false);
    }
  }

  Future<void> _processFrame(CameraImage frame) async {
    try {
      final jpeg = MemoryCameraEncoder.yuv420ToJpeg(frame);

      await widget.vault.store(jpeg);

      // Best-effort overwrite of the Dart buffer before dropping it.
      jpeg.fillRange(0, jpeg.length, 0);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Encrypted photo saved.'),
            duration: Duration(milliseconds: 700),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Encryption failed: $e')),
        );
      }
    } finally {
      processing = false;
      final c = controller;
      if (c != null && c.value.isStreamingImages) {
        await c.stopImageStream();
      }
      if (mounted) setState(() => streaming = false);
    }
  }

  Future<void> switchCamera() async {
    if (switching || appCameras.length < 2) return;
    switching = true;

    cameraIndex = (cameraIndex + 1) % appCameras.length;
    await _initCamera();

    switching = false;
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.inactive ||
        state == AppLifecycleState.paused ||
        state == AppLifecycleState.hidden) {
      widget.vault.lock();
      controller?.dispose();
      controller = null;
      streaming = false;
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    controller?.dispose();
    widget.vault.lock();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final c = controller;

    return Scaffold(
      backgroundColor: Colors.black,
      body: c == null || !c.value.isInitialized
          ? const Center(child: CircularProgressIndicator())
          : Stack(
              fit: StackFit.expand,
              children: [
                CameraPreview(c),
                SafeArea(
                  child: Column(
                    children: [
                      Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          IconButton(
                            icon: const Icon(Icons.lock_outline),
                            onPressed: () {
                              widget.vault.lock();
                              Navigator.of(context).pushAndRemoveUntil(
                                MaterialPageRoute(
                                  builder: (_) => const UnlockScreen(),
                                ),
                                (_) => false,
                              );
                            },
                          ),
                          IconButton(
                            icon: const Icon(Icons.flip_camera_android),
                            onPressed: switchCamera,
                          ),
                          IconButton(
                            icon: const Icon(Icons.photo_library_outlined),
                            onPressed: () {
                              Navigator.of(context).push(
                                MaterialPageRoute(
                                  builder: (_) =>
                                      GalleryScreen(vault: widget.vault),
                                ),
                              );
                            },
                          ),
                        ],
                      ),
                      const Spacer(),
                      GestureDetector(
                        onTap: capture,
                        child: Container(
                          width: 82,
                          height: 82,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: Colors.white,
                              width: 5,
                            ),
                          ),
                          child: Center(
                            child: Container(
                              width: 64,
                              height: 64,
                              decoration: const BoxDecoration(
                                shape: BoxShape.circle,
                                color: Colors.white,
                              ),
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 35),
                    ],
                  ),
                ),
              ],
            ),
    );
  }
}

// ---------------------------------------------------------------------------
// Gallery
// ---------------------------------------------------------------------------

class GalleryScreen extends StatefulWidget {
  final VaultController vault;

  const GalleryScreen({super.key, required this.vault});

  @override
  State<GalleryScreen> createState() => _GalleryScreenState();
}

class _GalleryScreenState extends State<GalleryScreen> {
  List<VaultItem> items = [];
  bool loading = true;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    final data = await widget.vault.storage.list();
    if (!mounted) return;
    setState(() {
      items = data;
      loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Encrypted Vault'),
        actions: [
          IconButton(
            icon: const Icon(Icons.lock),
            onPressed: () {
              widget.vault.lock();
              Navigator.of(context).pushAndRemoveUntil(
                MaterialPageRoute(builder: (_) => const UnlockScreen()),
                (_) => false,
              );
            },
          ),
        ],
      ),
      body: loading
          ? const Center(child: CircularProgressIndicator())
          : items.isEmpty
              ? const Center(child: Text('Vault is empty'))
              : GridView.builder(
                  padding: const EdgeInsets.all(3),
                  gridDelegate:
                      const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 3,
                    crossAxisSpacing: 3,
                    mainAxisSpacing: 3,
                  ),
                  itemCount: items.length,
                  itemBuilder: (_, index) {
                    final item = items[index];

                    return FutureBuilder<Uint8List>(
                      future: widget.vault.decrypt(item),
                      builder: (_, snap) {
                        if (!snap.hasData) {
                          return const Center(
                            child: CircularProgressIndicator(strokeWidth: 2),
                          );
                        }

                        return GestureDetector(
                          onTap: () {
                            Navigator.of(context).push(
                              MaterialPageRoute(
                                builder: (_) => PhotoViewer(
                                  vault: widget.vault,
                                  item: item,
                                ),
                              ),
                            );
                          },
                          child: Image.memory(
                            snap.data!,
                            fit: BoxFit.cover,
                          ),
                        );
                      },
                    );
                  },
                ),
    );
  }
}

class PhotoViewer extends StatelessWidget {
  final VaultController vault;
  final VaultItem item;

  const PhotoViewer({
    super.key,
    required this.vault,
    required this.item,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black,
        title: const Text('Protected View'),
      ),
      body: FutureBuilder<Uint8List>(
        future: vault.decrypt(item),
        builder: (_, snap) {
          if (!snap.hasData) {
            return const Center(child: CircularProgressIndicator());
          }

          return InteractiveViewer(
            minScale: 0.5,
            maxScale: 6,
            child: Center(
              child: Image.memory(
                snap.data!,
                fit: BoxFit.contain,
              ),
            ),
          );
        },
      ),
    );
  }
}
