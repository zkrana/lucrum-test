'use client';

export default function TermsOfService() {
  return (
    <div className="max-w-4xl mx-auto p-8 bg-white rounded-lg shadow-md">
      <h1 className="text-3xl font-bold mb-8">Terms of Service</h1>
      
      <div className="space-y-6">
        <section>
          <h2 className="text-2xl font-semibold mb-4">1. Acceptance of Terms</h2>
          <p className="text-gray-700 mb-4">
            By accessing or using our services, you agree to be bound by these Terms of Service. If you do not agree to these terms, please do not use our services.
          </p>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">2. User Accounts</h2>
          <div className="space-y-4 text-gray-700">
            <p>
              To access our services, you must:
            </p>
            <ul className="list-disc pl-6 space-y-2">
              <li>Create an account with valid credentials</li>
              <li>Maintain the security of your account credentials</li>
              <li>Notify us immediately of any unauthorized access</li>
              <li>Be at least 18 years old or have legal guardian consent</li>
            </ul>
          </div>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">3. Service Access and Training</h2>
          <div className="space-y-4 text-gray-700">
            <p>
              Users must:
            </p>
            <ul className="list-disc pl-6 space-y-2">
              <li>Complete required training modules before accessing full services</li>
              <li>Maintain active account status</li>
              <li>Comply with all platform rules and guidelines</li>
              <li>Not share access credentials with others</li>
            </ul>
          </div>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">4. Intellectual Property</h2>
          <p className="text-gray-700 mb-4">
            All content, features, and functionality of our services are owned by us and protected by international copyright, trademark, and other intellectual property laws.
          </p>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">5. User Conduct</h2>
          <div className="space-y-4 text-gray-700">
            <p>
              You agree not to:
            </p>
            <ul className="list-disc pl-6 space-y-2">
              <li>Use the service for any unlawful purpose</li>
              <li>Attempt to gain unauthorized access to any part of the service</li>
              <li>Interfere with or disrupt the service or servers</li>
              <li>Share confidential information or materials</li>
              <li>Upload malicious code or content</li>
            </ul>
          </div>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">6. Termination</h2>
          <p className="text-gray-700 mb-4">
            We reserve the right to terminate or suspend your account and access to our services at our sole discretion, without notice, for conduct that we believe violates these Terms of Service or is harmful to other users, us, or third parties, or for any other reason.
          </p>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">7. Disclaimer of Warranties</h2>
          <p className="text-gray-700 mb-4">
            Our services are provided "as is" without any warranties, expressed or implied. We do not guarantee that our services will be uninterrupted, secure, or error-free.
          </p>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">8. Limitation of Liability</h2>
          <p className="text-gray-700 mb-4">
            We shall not be liable for any indirect, incidental, special, consequential, or punitive damages resulting from your use or inability to use our services.
          </p>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">9. Changes to Terms</h2>
          <p className="text-gray-700 mb-4">
            We reserve the right to modify these terms at any time. We will notify users of any material changes via email or through our platform.
          </p>
        </section>

        <section>
          <h2 className="text-2xl font-semibold mb-4">10. Contact Information</h2>
          <p className="text-gray-700">
            For questions about these Terms of Service, please contact us at:
            <br />
            <a href="mailto:legal@lucrum.com" className="text-blue-600 hover:text-blue-800">
              legal@lucrum.com
            </a>
          </p>
        </section>

        <div className="text-sm text-gray-600 mt-8">
          Last Updated: March 1, 2024
        </div>
      </div>
    </div>
  );
}