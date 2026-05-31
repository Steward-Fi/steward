# steward-java

First-pass Java backend SDK for Steward API integrations.

The SDK uses only the Java standard library and can be compiled directly with
`javac`.

```java
import com.steward.sdk.CreateUserInput;
import com.steward.sdk.StewardClient;

StewardClient client = new StewardClient(StewardClient.config("https://api.steward.fi")
    .platformKey("steward_platform_...")
    .build());

var user = client.createUser(CreateUserInput.builder("my-app")
    .email("user@example.com")
    .build());
```

For production mutating calls, configure `requestSigningSecret`. The client
adds Steward request freshness, HMAC signature, and idempotency headers for
sensitive mutations.

```java
StewardClient client = new StewardClient(StewardClient.config("https://api.steward.fi")
    .appCredentials("app_...", "secret_...")
    .requestSigningSecret("stwd_req_...")
    .requestSigningKeyId("key_...")
    .build());
```

Local tests:

```sh
mkdir -p packages/java/build/classes
javac -d packages/java/build/classes $(find packages/java/src/main/java packages/java/src/test/java -name '*.java')
java -cp packages/java/build/classes com.steward.sdk.StewardClientTest
```
