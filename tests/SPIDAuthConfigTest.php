<?php

namespace Italia\SPIDAuth\Tests;

use DOMDocument;
use Italia\SPIDAuth\Exceptions\SPIDConfigurationException;
use Italia\SPIDAuth\SAML\SPIDAuth as SPIDSAMLAuth;
use OneLogin\Saml2\Settings;
use Orchestra\Testbench\TestCase;
use ReflectionClass;

class SPIDAuthConfigTest extends TestCase
{
    public function testAuthnRequestKeepsSpidRequiredFieldsWithoutVendorPatch()
    {
        $settings = new Settings($this->getSPIDAuthConfig());
        $request = (new SPIDSAMLAuth($this->getSPIDAuthConfig()))->buildAuthnRequest($settings, true, false, true, 'ignored-subject');
        $document = new DOMDocument();
        $document->loadXML($request->getXML());

        $root = $document->documentElement;
        $issuer = $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')->item(0);
        $nameIdPolicy = $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:protocol', 'NameIDPolicy')->item(0);

        $this->assertSame('0', $root->getAttribute('AttributeConsumingServiceIndex'));
        $this->assertSame('true', $root->getAttribute('ForceAuthn'));
        $this->assertSame(config('spid-auth.sp_entity_id'), $issuer->getAttribute('NameQualifier'));
        $this->assertSame('urn:oasis:names:tc:SAML:2.0:nameid-format:entity', $issuer->getAttribute('Format'));
        $this->assertFalse($nameIdPolicy->hasAttribute('AllowCreate'));
        $this->assertFalse($root->hasAttribute('ProviderName'));
        $this->assertSame(0, $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Subject')->length);
        $this->assertSame($request->getXML(), gzinflate(base64_decode($request->getRequest())));
    }

    public function testLogoutRequestKeepsSpidRequiredFieldsWithoutVendorPatch()
    {
        $config = $this->getSPIDAuthConfig();
        $settings = new Settings($config);
        $request = (new SPIDSAMLAuth($config))->buildLogoutRequest($settings);
        $document = new DOMDocument();
        $document->loadXML($request->getXML());

        $root = $document->documentElement;
        $issuer = $document->getElementsByTagNameNS('urn:oasis:names:tc:SAML:2.0:assertion', 'Issuer')->item(0);

        $this->assertSame($config['idp']['entityId'], $root->getAttribute('Destination'));
        $this->assertSame($config['sp']['entityId'], $issuer->getAttribute('NameQualifier'));
        $this->assertSame('urn:oasis:names:tc:SAML:2.0:nameid-format:entity', $issuer->getAttribute('Format'));
        $this->assertSame($request->getXML(), gzinflate(base64_decode($request->getRequest())));
    }

    public function testLoginAndLogoutRedirectsEncodeTheSpidRequests()
    {
        $config = $this->getSPIDAuthConfig();
        $auth = new SPIDSAMLAuth($config);

        $loginUrl = $auth->login('relay', [], true, false, true);
        parse_str(parse_url($loginUrl, PHP_URL_QUERY), $loginParameters);
        $this->assertSame($auth->getLastRequestXML(), gzinflate(base64_decode($loginParameters['SAMLRequest'])));
        $this->assertStringContainsString('AttributeConsumingServiceIndex=', $auth->getLastRequestXML());

        $logoutUrl = $auth->logout('relay', [], null, null, true);
        parse_str(parse_url($logoutUrl, PHP_URL_QUERY), $logoutParameters);
        $this->assertSame($auth->getLastRequestXML(), gzinflate(base64_decode($logoutParameters['SAMLRequest'])));

        $document = new DOMDocument();
        $document->loadXML($auth->getLastRequestXML());
        $this->assertSame($config['idp']['entityId'], $document->documentElement->getAttribute('Destination'));
    }

    public function testLogoutResponseTrimsIssuer()
    {
        $config = $this->getSPIDAuthConfig();
        $response = base64_encode('<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>  idp-issuer  </saml:Issuer></samlp:LogoutResponse>');
        $logoutResponse = (new SPIDSAMLAuth($config))->buildLogoutResponse(new Settings($config), $response);

        $this->assertSame('idp-issuer', $logoutResponse->getIssuer());
    }

    public function testMissingEntityId()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider entity ID not set');
        config(['spid-auth.sp_entity_id' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingAcsIndex()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider AssertionConsumerService index not set');
        config(['spid-auth.sp_acs_index' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingAttributeIndex()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider AttributeConsumingService index not set');
        config(['spid-auth.sp_attributes_index' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingBaseURL()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider base URL not set');
        config(['spid-auth.sp_base_url' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingServiceName()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider service name not set');
        config(['spid-auth.sp_service_name' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingRequestedAttributes()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider requested attributes not set');
        config(['spid-auth.sp_requested_attributes' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingCertificate()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider certificate not set');
        config(['spid-auth.sp_certificate' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingPrivateKey()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Service provider private key not set');
        config(['spid-auth.sp_private_key' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testCertificateFile()
    {
        $certificate = config('spid-auth.sp_certificate');
        config(['spid-auth.sp_certificate' => null]);
        config(['spid-auth.sp_certificate_file' => __DIR__ . '/secrets/certificate.crt']);
        $SPIDAuthConfig = $this->getSPIDAuthConfig();
        $this->assertEquals($certificate, $SPIDAuthConfig['sp']['x509cert']);
    }

    public function testPrivateKeyFile()
    {
        $privateKey = config('spid-auth.sp_private_key');
        config(['spid-auth.sp_private_key' => null]);
        config(['spid-auth.sp_private_key_file' => __DIR__ . '/secrets/private.key']);
        $SPIDAuthConfig = $this->getSPIDAuthConfig();
        $this->assertEquals($privateKey, $SPIDAuthConfig['sp']['privateKey']);
    }

    public function testInvalidCertificateFile()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Certificate not valid');
        config(['spid-auth.sp_certificate' => null]);
        config(['spid-auth.sp_certificate_file' => __DIR__ . '/secrets/certificate_invalid.crt']);
        $SPIDAuthConfig = $this->getSPIDAuthConfig();
    }

    public function testInvalidPrivateKeyFile()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('Private key not valid');
        config(['spid-auth.sp_private_key' => null]);
        config(['spid-auth.sp_private_key_file' => __DIR__ . '/secrets/private_invalid.key']);
        $SPIDAuthConfig = $this->getSPIDAuthConfig();
    }

    public function testMissingSpidLevel()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID authentication level name wrong or not set');
        config(['spid-auth.sp_spid_level' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testMissingContactPerson()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID contact persons not set');
        config(['spid-auth.sp_contact_persons' => null]);
        $this->getSPIDAuthConfig();
    }

    public function testPrivatePublicInconsistency()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID Public and Private are mutually exclusive');
        config(['spid-auth.sp_contact_persons' => [
            'other' => [
                'Public' => true,
            ],
            'billing' => [
                'Private' => true,
            ],
        ]]);
        $this->getSPIDAuthConfig();
    }

    public function testPrivateRequiresVATNumber()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID Private requires VATNumber');
        config(['spid-auth.sp_contact_persons' => [
            'other' => [
                'Private' => true,
            ],
            'billing' => [
                'Private' => true,
            ],
        ]]);
        $this->getSPIDAuthConfig();
    }

    public function testPublicRequiresIPACode()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID Public requires IPACode');
        config(['spid-auth.sp_contact_persons' => [
            'other' => [
                'Public' => true,
            ],
        ]]);
        $this->getSPIDAuthConfig();
    }

    public function testContactRequiresEmailAddress()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID missing email address for this contacts: other');
        config(['spid-auth.sp_contact_persons' => [
            'other' => [
                'Public' => true,
                'IPACode' => '12345',
            ],
        ]]);
        $this->getSPIDAuthConfig();
    }

    public function testInvalidSpidLevel()
    {
        $this->withoutExceptionHandling();
        $this->expectException(SPIDConfigurationException::class);
        $this->expectExceptionMessage('SPID authentication level name wrong or not set');
        config(['spid-auth.sp_spid_level' => 'https://www.spid.gov.it/SpidL4']);
        $this->getSPIDAuthConfig();
    }

    protected function getPackageProviders($app)
    {
        return ['Italia\SPIDAuth\ServiceProvider'];
    }

    protected function getSPIDAuthConfig()
    {
        $SPIDAuth = $this->app->make('SPIDAuth');
        $reflectedSPIDAuth = new ReflectionClass(get_class($SPIDAuth));
        $getSAMLConfig = $reflectedSPIDAuth->getMethod('getSAMLConfig');
        $getSAMLConfig->setAccessible(true);

        return $getSAMLConfig->invokeArgs($SPIDAuth, ['test']);
    }
}
