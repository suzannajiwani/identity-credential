/*
 * Copyright 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.identity.android.direct_access;

import static org.junit.Assert.fail;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class DirectAccessProvisionTest extends DirectAccessTest {

  @Override
  @Before
  public void init() {
    super.init(TransportType.SMARTCARDIO);
  }

  @Override
  @After
  public void reset() {
    super.reset();
  }

  private MDocDocument createMDocCredential(String docName, String docType, byte[] challenge,
                                            int numSigningKeys, Duration duration) throws IOException, CertificateException {
    mDocStore = new MDocStore(mTransport, mStorageEngine);
    return mDocStore.createDocument(docName, docType, challenge,
        numSigningKeys, Duration.ofDays(365));
  }

  @Test
  public void provisionSuccess() {
    int numSigningKeys = 1;
    MDocDocument credential = null;
    try {
      waitForConnection();
      mDocName = "mDL";
      byte[] challenge = "challenge".getBytes();

      credential = createMDocCredential(mDocName, DocumentDataParser.MDL_DOC_TYPE,
              challenge, numSigningKeys, Duration.ofDays(365));
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
    List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
    Assert.assertTrue(certificates.size() >= 1);
    Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
    List<MDocDocument.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
            Duration.ofDays(180));
    Assert.assertEquals(numSigningKeys, certificationRequests.size());
    // Provision
    byte[] encodedCredData = new DirectAccessTestUtils().createCredentialData(mContext,
            certificationRequests.get(0), DocumentDataParser.MDL_DOC_TYPE, null);
    credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
  }

  @Test
  public void createCredentialWithInvalidDocTypeThrowsIllegalArgumentException() {
    try {
      waitForConnection();
      mDocName = "myDoc";
      String invalidDocType = "invalid-docType";
      byte[] challenge = "challenge".getBytes();
      int numSigningKeys = 1;
      createMDocCredential(mDocName, invalidDocType, challenge, numSigningKeys,
          Duration.ofDays(365));
      fail("Expected to fail when invalid docType is passed.");
    } catch (IllegalArgumentException expected) {
      // Excepted exception.
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void provisionWithEmptyCredentialDataThrowsIllegalArgumentException() {
    MDocDocument credential = null;
    int numSigningKeys = 0;
    try {
      mDocName = "mDL";
      credential = null;
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      numSigningKeys = 1;
      credential = createMDocCredential(mDocName, DocumentDataParser.MDL_DOC_TYPE,
          challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }

    List<MDocDocument.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
        Duration.ofDays(180));
    Assert.assertEquals(numSigningKeys, certificationRequests.size());
    try {
      // Provision
      byte[] encodedCredData = {};
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      fail("Expected to fail when empty credential data is passed.");
    } catch (IllegalArgumentException e) {
      // Expected Exception
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void provisionWithInvalidCredentialDataThrowsIllegalArgumentException() {
    MDocDocument credential = null;
    int numSigningKeys = 0;
    try {
      mDocName = "mDL";
      credential = null;
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      numSigningKeys = 1;
      credential = createMDocCredential(mDocName, DocumentDataParser.MDL_DOC_TYPE,
          challenge, numSigningKeys, Duration.ofDays(365));
      List<X509Certificate> certificates = credential.getCredentialKeyCertificateChain();
      Assert.assertTrue(certificates.size() >= 1);
      Assert.assertEquals(numSigningKeys, credential.getNumSigningKeys());
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }

    List<MDocDocument.MDocSigningKeyCertificationRequest> certificationRequests = credential.getSigningKeyCertificationRequests(
        Duration.ofDays(180));
    Assert.assertEquals(numSigningKeys, certificationRequests.size());
    try {
      // Provision
      // TODO loop through different types of invalid cbor data.
      byte[] encodedCredData = "invalid-cred-data".getBytes(StandardCharsets.UTF_8);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      fail("Expected to fail when empty credential data is passed.");
    } catch (IllegalArgumentException e) {
      // Expected Exception
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void lookupWithDifferentDocNameThrowsIllegalArgumentException() {
    MDocDocument credential = null;
    int numSigningKeys = 0;
    try {
      mDocName = "mDL";
      waitForConnection();
      byte[] challenge = "challenge".getBytes();
      numSigningKeys = 1;
      credential = createMDocCredential(mDocName, DocumentDataParser.MDL_DOC_TYPE,
          challenge, numSigningKeys, Duration.ofDays(365));
      Assert.assertNotNull(credential);
      Assert.assertNull(mDocStore.lookupDocument("_"));
    } catch (Exception e) {
      fail("Unexpected Exception " + e);
    }
  }

  @Test
  public void createCredentialWithLargeChallenge() {
  }

}
