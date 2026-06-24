package ro.roeid.attested_secure_keys_example;

import androidx.test.rule.ActivityTestRule;
import dev.flutter.plugins.integration_test.FlutterTestRunner;
import org.junit.Rule;
import org.junit.runner.RunWith;

// Instrumentation harness that drives the Dart integration_test suite
// (example/integration_test/plugin_integration_test.dart) on a real device via
// Firebase Test Lab. MainActivity lives in this same package, so no import is
// needed. See .github/workflows/device-tests.yml.
@RunWith(FlutterTestRunner.class)
public class MainActivityTest {
  @Rule
  public ActivityTestRule<MainActivity> rule = new ActivityTestRule<>(MainActivity.class);
}
