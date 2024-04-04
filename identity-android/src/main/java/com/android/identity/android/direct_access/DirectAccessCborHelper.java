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

import com.android.identity.cbor.Cbor;
import com.android.identity.cbor.DataItem;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class DirectAccessCborHelper {
  private static final String TAG = "DirectAccessCborHelper";
  public static final int KEY_CERT = 0x01;
  public static final int KEY_ENC_DATA = 0x00;

  public PresentationPackage decodePresentationPackage(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("createPresentationPackage failed. Response status: "+ status);
    }
    byte[] input = Arrays.copyOf(response, response.length-2);

    PresentationPackage pp = null;
    DataItem map = Cbor.decode(input);
    Set<DataItem> keys = map.getAsMap().keySet();
    pp = new PresentationPackage();
    for (DataItem keyItem : keys) {
      int value = (int) keyItem.getAsNumber();
      switch (value) {
        case KEY_CERT:
          DataItem bStrItem = map.get(keyItem);
          byte[] certData = bStrItem.getAsBstr();
          List<X509Certificate> credentialKeyCert = null;
          try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bis = new ByteArrayInputStream(certData);
            credentialKeyCert = new ArrayList<>();
            credentialKeyCert.add((X509Certificate) cf.generateCertificate(bis));
          } catch (CertificateException e) {
            throw new IllegalStateException("Error generating signing certificate from response", e);
          }
          pp.signingCert = credentialKeyCert;
          break;
        case KEY_ENC_DATA:
          DataItem encBytesItem = map.get(keyItem);
          pp.encryptedData = encBytesItem.getAsBstr();
          break;
        default:
          throw new IllegalStateException("createPresentationPackage unknown key item");
      }
    }
    return pp;
  }

  public boolean isOkResponse(byte[] response) {
    int status = getApduStatus(response);
    return DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK == status;
  }

  public List<X509Certificate> decodeCredentialKeyResponse(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("CreateCredential failed. Response status: "+ status);
    }
    byte[] input = Arrays.copyOf(response, response.length-2);
    // TODO DirectAccess Applet returns only one certificate and not chain.
    //  TODO This logic has to be updated if more certificates are returned from Applet.
    List<X509Certificate> credentialKeyCert = null;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream bis = new ByteArrayInputStream(input);
      credentialKeyCert = new ArrayList<>();
      credentialKeyCert.add((X509Certificate) cf.generateCertificate(bis));
    } catch (CertificateException e) {
      throw new IllegalStateException("Error generating certificate from response", e);
    }
    return credentialKeyCert;
  }

  public byte[] decodeProvisionResponse(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("Begin Provision failed. Response status: "+ status);
    }
    if (response.length > 2) {
      byte[] input = Arrays.copyOf(response, response.length - 2);
      return Cbor.decode(input).getAsBstr();
    }
    return null;
  }

  public void decodeDeleteCredential(byte[] response) {
    int status = getApduStatus(response);
    if (DirectAccessAPDUHelper.APDU_RESPONSE_STATUS_OK != status) {
      throw new IllegalStateException("createPresentationPackage failed. Response status: "+ status);
    }
  }

  private int getApduStatus(byte[] cborResponse) {
    // TODO Move this a common place in Transport.
    DirectAccessAPDUHelper apduHelper = new DirectAccessAPDUHelper();
    return apduHelper.getAPDUResponseStatus(cborResponse);
  }

}
