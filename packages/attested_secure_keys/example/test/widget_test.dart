// Basic widget test for the example app.

import 'package:attested_secure_keys_example/main.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('renders the demo scaffold with action buttons', (tester) async {
    await tester.pumpWidget(const MyApp());

    // The app bar title and the primary actions are present.
    expect(find.text('attested_secure_keys'), findsOneWidget);
    expect(find.text('Capabilities'), findsOneWidget);
    expect(find.text('Generate'), findsOneWidget);
  });
}
