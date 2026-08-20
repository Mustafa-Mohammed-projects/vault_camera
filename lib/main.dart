import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:camera/camera.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:path_provider/path_provider.dart';
import 'package:encrypt/encrypt.dart' as enc;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';

// متغير عام للوصول إلى كاميرات الجهاز
List<CameraDescription> cameras = [];

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // طلب أذونات Android 13+ والكاميرا
  await [
    Permission.camera,
    Permission.photos,
    Permission.biometrics,
  ].request();

  try {
    cameras = await availableCameras();
  } catch (e) {
    debugPrint("Failed to initialize camera: $e");
  }

  runApp(const VaultApp());
}

// =============================================================================
// 1. MODEL (نموذج بيانات الصورة المشفرة)
// =============================================================================
class VaultItem {
  final String filePath;
  final String ivBase64;
  final DateTime createdAt;

  VaultItem({
    required this.filePath,
    required this.ivBase64,
    required this.createdAt,
  });

  Map<String, dynamic> toJson() => {
        'filePath': filePath,
        'ivBase64': ivBase64,
        'createdAt': createdAt.toIso8601String(),
      };

  factory VaultItem.fromJson(Map<String, dynamic> json) => VaultItem(
        filePath: json['filePath'],
        ivBase64: json['ivBase64'],
        createdAt: DateTime.parse(json['createdAt']),
      );
}

// =============================================================================
// 2. SERVICES (محرك التشفير والتخزين)
// =============================================================================
class EncryptionService {
  final _secureStorage = const FlutterSecureStorage();
  final _localAuth = LocalAuthentication();
  static const _keyAlias = 'vault_master_key';

  Future<bool> authenticate() async {
    final canCheck = await _localAuth.canCheckBiometrics;
    if (!canCheck) return false;
    return await _localAuth.authenticate(
      localizedReason: 'Authenticate to access Vault keys',
      options: const AuthenticationOptions(biometricOnly: true),
    );
  }

  Future<enc.Key> _getOrCreateKey() async {
    String? base64Key = await _secureStorage.read(key: _keyAlias);
    if (base64Key == null) {
      final key = enc.Key.fromSecureRandom(32); // 256-bit AES Key
      await _secureStorage.write(key: _keyAlias, value: key.base64);
      return key;
    }
    return enc.Key.fromBase64(base64Key);
  }

  Future<Map<String, dynamic>> encryptImage(Uint8List imageBytes) async {
    final key = await _getOrCreateKey();
    final iv = enc.IV.fromSecureRandom(16);
    final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.cbc));
    final encrypted = encrypter.encryptBytes(imageBytes, iv: iv);
    return {
      'encryptedBytes': encrypted.bytes,
      'iv': iv.base64,
    };
  }

  Future<Uint8List> decryptVaultFile(Uint8List encryptedBytes, String ivBase64) async {
    final key = await _getOrCreateKey();
    final iv = enc.IV.fromBase64(ivBase64);
    final encrypter = enc.Encrypter(enc.AES(key, mode: enc.AESMode.cbc));
    final encrypted = enc.Encrypted(encryptedBytes);
    return Uint8List.fromList(encrypter.decryptBytes(encrypted, iv: iv));
  }
}

class VaultStorageService {
  final EncryptionService _encryptionService = EncryptionService();

  Future<Directory> _getVaultDirectory() async {
    final docsDir = await getApplicationDocumentsDirectory();
    final vaultDir = Directory('${docsDir.path}/vault');
    if (!await vaultDir.exists()) {
      await vaultDir.create(recursive: true);
    }
    return vaultDir;
  }

  Future<void> saveEncryptedPhoto(Uint8List imageBytes) async {
    final dir = await _getVaultDirectory();
    final encryptedData = await _encryptionService.encryptImage(imageBytes);

    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final photoFile = File('${dir.path}/img_$timestamp.vault');
    final metaFile = File('${dir.path}/img_$timestamp.meta');

    await photoFile.writeAsBytes(encryptedData['encryptedBytes']);

    final item = VaultItem(
      filePath: photoFile.path,
      ivBase64: encryptedData['iv'],
      createdAt: DateTime.now(),
    );
    await metaFile.writeAsString(jsonEncode(item.toJson()));
  }

  Future<List<VaultItem>> loadVaultItems() async {
    final dir = await _getVaultDirectory();
    final List<FileSystemEntity> files = dir.listSync();
    List<VaultItem> items = [];

    for (var file in files) {
      if (file.path.endsWith('.meta')) {
        final content = await File(file.path).readAsString();
        items.add(VaultItem.fromJson(jsonDecode(content)));
      }
    }
    items.sort((a, b) => b.createdAt.compareTo(a.createdAt));
    return items;
  }

  Future<Uint8List> decryptItem(VaultItem item) async {
    final encryptedBytes = await File(item.filePath).readAsBytes();
    return await _encryptionService.decryptVaultFile(encryptedBytes, item.ivBase64);
  }
}

// =============================================================================
// 3. UI SCREENS & WIDGETS (الشاشات وواجهة المستخدم)
// =============================================================================
class VaultApp extends StatelessWidget {
  const VaultApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Vault Camera',
      debugShowCheckedModeBanner: false,
      theme: ThemeData.dark(useMaterial3: true),
      home: const MainNavigationScreen(),
    );
  }
}

class MainNavigationScreen extends StatefulWidget {
  const MainNavigationScreen({Key? key}) : super(key: key);

  @override
  _MainNavigationScreenState createState() => _MainNavigationScreenState();
}

class _MainNavigationScreenState extends State<MainNavigationScreen> {
  int _currentIndex = 0;

  @override
  Widget build(BuildContext context) {
    final pages = [
      cameras.isNotEmpty
          ? CameraScreen(cameras: cameras)
          : const Center(child: Text("لا توجد كاميرا متوفرة")),
      const GalleryScreen(),
    ];

    return Scaffold(
      body: pages[_currentIndex],
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _currentIndex,
        backgroundColor: Colors.black,
        selectedItemColor: Colors.amber,
        unselectedItemColor: Colors.white54,
        onTap: (index) => setState(() => _currentIndex = index),
        items: const [
          BottomNavigationBarItem(icon: Icon(Icons.camera_alt), label: 'الكاميرا'),
          BottomNavigationBarItem(icon: Icon(Icons.photo_library), label: 'المعرض المشفر'),
        ],
      ),
    );
  }
}

class CameraScreen extends StatefulWidget {
  final List<CameraDescription> cameras;
  const CameraScreen({Key? key, required this.cameras}) : super(key: key);

  @override
  _CameraScreenState createState() => _CameraScreenState();
}

class _CameraScreenState extends State<CameraScreen> {
  late CameraController _controller;
  final VaultStorageService _storageService = VaultStorageService();
  bool _isCapturing = false;

  @override
  void initState() {
    super.initState();
    _controller = CameraController(widget.cameras[0], ResolutionPreset.max);
    _controller.initialize().then((_) {
      if (!mounted) return;
      setState(() {});
    });
  }

  Future<void> _captureAndEncrypt() async {
    if (_isCapturing) return;
    setState(() => _isCapturing = true);

    try {
      final XFile photo = await _controller.takePicture();
      final bytes = await photo.readAsBytes();

      // التشفير والحفظ المباشر
      await _storageService.saveEncryptedPhoto(bytes);

      // مسح الكاش المؤقت للكاميرا فوراً
      final rawFile = File(photo.path);
      if (await rawFile.exists()) {
        await rawFile.delete();
      }

      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('تم التشفير والحفظ بنجاح!')),
      );
    } catch (e) {
      debugPrint("Capture error: $e");
    } finally {
      setState(() => _isCapturing = false);
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!_controller.value.isInitialized) {
      return const Center(child: CircularProgressIndicator());
    }

    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        children: [
          Positioned.fill(
            child: AspectRatio(
              aspectRatio: 16 / 9,
              child: CameraPreview(_controller),
            ),
          ),
          Align(
            alignment: Alignment.bottomCenter,
            child: Padding(
              padding: const EdgeInsets.only(bottom: 40),
              child: FloatingActionButton(
                backgroundColor: _isCapturing ? Colors.grey : Colors.white,
                onPressed: _captureAndEncrypt,
                child: const Icon(Icons.camera, color: Colors.black, size: 30),
              ),
            ),
          )
        ],
      ),
    );
  }
}

class GalleryScreen extends StatefulWidget {
  const GalleryScreen({Key? key}) : super(key: key);

  @override
  _GalleryScreenState createState() => _GalleryScreenState();
}

class _GalleryScreenState extends State<GalleryScreen> {
  final VaultStorageService _storageService = VaultStorageService();
  late Future<List<VaultItem>> _vaultItemsFuture;

  @override
  void initState() {
    super.initState();
    _vaultItemsFuture = _storageService.loadVaultItems();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('المعرض المشفر'),
        backgroundColor: Colors.black,
      ),
      backgroundColor: Colors.black,
      body: FutureBuilder<List<VaultItem>>(
        future: _vaultItemsFuture,
        builder: (context, snapshot) {
          if (snapshot.connectionState == ConnectionState.waiting) {
            return const Center(child: CircularProgressIndicator());
          }
          if (!snapshot.hasData || snapshot.data!.isEmpty) {
            return const Center(
              child: Text('لا توجد صور مشفرة محفوطة.', style: TextStyle(color: Colors.white54)),
            );
          }

          final items = snapshot.data!;
          return GridView.builder(
            padding: const EdgeInsets.all(8),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 3,
              crossAxisSpacing: 8,
              mainAxisSpacing: 8,
            ),
            itemCount: items.length,
            itemBuilder: (context, index) {
              return VaultGridItem(
                item: items[index],
                storageService: _storageService,
              );
            },
          );
        },
      ),
    );
  }
}

class VaultGridItem extends StatelessWidget {
  final VaultItem item;
  final VaultStorageService storageService;

  const VaultGridItem({
    Key? key,
    required this.item,
    required this.storageService,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return FutureBuilder<Uint8List>(
      future: storageService.decryptItem(item),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return Container(color: Colors.grey[900], child: const Icon(Icons.lock, color: Colors.white24));
        }
        if (snapshot.hasError || !snapshot.hasData) {
          return Container(color: Colors.red[900], child: const Icon(Icons.error));
        }

        return GestureDetector(
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => PhotoViewScreen(imageBytes: snapshot.data!),
              ),
            );
          },
          child: Image.memory(
            snapshot.data!,
            fit: BoxFit.cover,
          ),
        );
      },
    );
  }
}

class PhotoViewScreen extends StatelessWidget {
  final Uint8List imageBytes;

  const PhotoViewScreen({Key? key, required this.imageBytes}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: Center(
        child: InteractiveViewer(
          child: Image.memory(imageBytes),
        ),
      ),
    );
  }
}
