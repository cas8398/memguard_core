import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const MethodChannel channel = MethodChannel('com.memguard/storage');

  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    // Optional: mock the platform channel for testing
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      switch (methodCall.method) {
        case 'store':
          return true;
        case 'retrieve':
          if (methodCall.arguments['key'] == 'missing') return null;
          return true;
        case 'retrieveDirect':
          if (methodCall.arguments['key'] == 'secret') return 'value';
          return null;
        case 'delete':
        case 'contains':
        case 'getStats':
        case 'cleanupAll':
          return true;
        default:
          return null;
      }
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('Store key returns true', () async {
    final result =
        await channel.invokeMethod('store', {'key': 'k1', 'value': 'v1'});
    expect(result, true);
  });

  test('RetrieveDirect returns plaintext', () async {
    final result =
        await channel.invokeMethod('retrieveDirect', {'key': 'secret'});
    expect(result, 'value');
  });

  test('Retrieve missing key returns null', () async {
    final result = await channel.invokeMethod('retrieve', {'key': 'missing'});
    expect(result, null);
  });

  test('Delete key returns true', () async {
    final result = await channel.invokeMethod('delete', {'key': 'k1'});
    expect(result, true);
  });
}
