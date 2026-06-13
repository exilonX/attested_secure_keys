package ro.roeid.attested_secure_keys_example

import io.flutter.embedding.android.FlutterFragmentActivity

// FlutterFragmentActivity (a FragmentActivity) is required so that
// attested_secure_keys can attach BiometricPrompt for auth-gated keys.
class MainActivity : FlutterFragmentActivity()
