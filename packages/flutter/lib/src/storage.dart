abstract interface class StewardSessionStorage {
  Future<String?> getItem(String key);
  Future<void> setItem(String key, String value);
  Future<void> removeItem(String key);
}

class MemoryStewardSessionStorage implements StewardSessionStorage {
  final Map<String, String> _store = <String, String>{};

  @override
  Future<String?> getItem(String key) async => _store[key];

  @override
  Future<void> setItem(String key, String value) async {
    _store[key] = value;
  }

  @override
  Future<void> removeItem(String key) async {
    _store.remove(key);
  }
}

class NamespacedStewardSessionStorage implements StewardSessionStorage {
  NamespacedStewardSessionStorage(this.inner, {required this.namespace});

  final StewardSessionStorage inner;
  final String namespace;

  String _key(String key) => '$namespace:$key';

  @override
  Future<String?> getItem(String key) => inner.getItem(_key(key));

  @override
  Future<void> setItem(String key, String value) => inner.setItem(_key(key), value);

  @override
  Future<void> removeItem(String key) => inner.removeItem(_key(key));
}
