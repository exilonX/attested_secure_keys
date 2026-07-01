#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint attested_secure_keys.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'attested_secure_keys_ios'
  s.version          = '0.1.0-dev.1'
  s.summary          = 'Hardware-backed, attestable EC P-256 keys for Flutter: Android Keystore/StrongBox and iOS Secure Enclave, non-exportable, ES256/JOSE output, with verifiable key attestation.'
  s.description      = <<-DESC
Hardware-backed, attestable EC P-256 keys for Flutter: Android Keystore/StrongBox and iOS Secure Enclave, non-exportable, ES256/JOSE output, with verifiable key attestation.
                       DESC
  s.homepage         = 'https://github.com/exilonX/attested_secure_keys'
  s.license          = { :type => 'Apache-2.0', :file => '../LICENSE' }
  s.author           = 'Ionel Merca'
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # If your plugin requires a privacy manifest, for example if it uses any
  # required reason APIs, update the PrivacyInfo.xcprivacy file to describe your
  # plugin's privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  # s.resource_bundles = {'attested_secure_keys_privacy' => ['Resources/PrivacyInfo.xcprivacy']}
end
