import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

void main() {
  runApp(const MemGuardExampleApp());
}

class MemGuardExampleApp extends StatelessWidget {
  const MemGuardExampleApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'MemGuard Core Example',
      theme: ThemeData(primarySwatch: Colors.blue),
      home: const MemGuardHomePage(),
    );
  }
}

class MemGuardHomePage extends StatefulWidget {
  const MemGuardHomePage({super.key});

  @override
  State<MemGuardHomePage> createState() => _MemGuardHomePageState();
}

class _MemGuardHomePageState extends State<MemGuardHomePage> {
  static const MethodChannel _channel = MethodChannel('com.memguard/storage');

  final TextEditingController _keyController = TextEditingController();
  final TextEditingController _valueController = TextEditingController();

  String _output = '';

  Future<void> _store() async {
    final key = _keyController.text;
    final value = _valueController.text;

    try {
      final result =
          await _channel.invokeMethod('store', {'key': key, 'value': value});
      setState(() {
        _output = 'Store result: $result';
      });
    } on PlatformException catch (e) {
      setState(() {
        _output = 'Store error: ${e.message}';
      });
    }
  }

  Future<void> _retrieve() async {
    final key = _keyController.text;

    try {
      final result = await _channel.invokeMethod('retrieve', {'key': key});
      setState(() {
        _output = 'Retrieve result: $result';
      });
    } on PlatformException catch (e) {
      setState(() {
        _output = 'Retrieve error: ${e.message}';
      });
    }
  }

  Future<void> _delete() async {
    final key = _keyController.text;

    try {
      final result = await _channel.invokeMethod('delete', {'key': key});
      setState(() {
        _output = 'Delete result: $result';
      });
    } on PlatformException catch (e) {
      setState(() {
        _output = 'Delete error: ${e.message}';
      });
    }
  }

  Future<void> _retrieveDirect() async {
    final key = _keyController.text;

    try {
      final result =
          await _channel.invokeMethod('retrieveDirect', {'key': key});
      setState(() {
        _output = 'Direct retrieve: $result';
      });
    } on PlatformException catch (e) {
      setState(() {
        _output = 'Direct retrieve error: ${e.message}';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('MemGuard Core Example')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            TextField(
                controller: _keyController,
                decoration: const InputDecoration(labelText: 'Key')),
            const SizedBox(height: 8),
            TextField(
                controller: _valueController,
                decoration: const InputDecoration(labelText: 'Value')),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                ElevatedButton(onPressed: _store, child: const Text('Store')),
                ElevatedButton(
                    onPressed: _retrieve, child: const Text('Retrieve')),
                ElevatedButton(onPressed: _delete, child: const Text('Delete')),
              ],
            ),
            const SizedBox(height: 8),
            ElevatedButton(
                onPressed: _retrieveDirect,
                child: const Text('Retrieve Direct')),
            const SizedBox(height: 24),
            Expanded(child: SingleChildScrollView(child: Text(_output))),
          ],
        ),
      ),
    );
  }
}
