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

import androidx.annotation.NonNull;

import com.android.identity.cbor.ArrayBuilder;
import com.android.identity.cbor.Bstr;
import com.android.identity.cbor.Cbor;
import com.android.identity.cbor.CborBuilder;
import com.android.identity.cbor.DataItem;
import com.android.identity.android.util.NfcUtil;
import com.android.identity.cbor.CborMap;
import com.android.identity.cbor.MapBuilder;
import com.android.identity.direct_access.DirectAccessTransport;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.Logger;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class MDocDocument {

  private static final String TAG = "MDocDocument";
  // private static final byte[] DIRECT_ACCESS_PROVISIONING_APPLET_ID = {
  //     (byte)0xA0, 0x00, 0x00, 0x04, 0x76, 0x57, 0x56, 0x52, 0x43, 0x4F, 0x52, 0x45,0x30,
  //     0x00, 0x01, 0x01};
  public static final byte[] DIRECT_ACCESS_PROVISIONING_APPLET_ID = {
      (byte) 0xA0, 0x00, 0x00, 0x02, 0x48, 0x00, 0x01, 0x01, 0x01};
  public static final String MDOC_CREDENTIAL_PREFIX = "DA_Credential_";
  private static final String MDOC_PREFIX = "DA_AndroidKeystore_";
  private static final long CREDENTIAL_KEY_VALID_DURATION = (365 * 24 * 60 * 60 * 1000);
  private static final byte PROVISION_BEGIN = 0;
  private static final byte PROVISION_UPDATE = 1;
  private static final byte PROVISION_FINISH = 2;
  private static final int SLOT_0 = 0;
  private final StorageEngine mStorageEngine;
  private final DirectAccessTransport mTransport;
  private int mNumSigningKeys;
  private Duration mSigningKeyMinValidDuration;
  private String mDocName;
  private String mDocType;
  private int mSlot;
  DirectAccessCborHelper mCborHelper;
  DirectAccessAPDUHelper mApduHelper;

  private MDocDocument(@NonNull StorageEngine storageEngine,
                       @NonNull DirectAccessTransport mTransport) {
    this.mStorageEngine = storageEngine;
    this.mTransport = mTransport;
  }

  private void selectProvisionApplet() {
    try {
      byte[] selectApdu = NfcUtil.createApduApplicationSelect(DIRECT_ACCESS_PROVISIONING_APPLET_ID);
      byte[] response = mTransport.sendData(selectApdu);
      if (!mCborHelper.isOkResponse(response)) {
        throw new IllegalStateException("Failed to select Provision Applet");
      }
    } catch (IOException e) {
      throw new IllegalStateException("Failed to send select Provision Applet APDU command");
    }
  }
  public static MDocDocument create(@NonNull String name, @NonNull String docType,
                                    @NonNull byte[] challenge, int numSigningKeys, @NonNull Duration signingKeyMinValidDuration,
                                    @NonNull StorageEngine storageEngine, @NonNull DirectAccessTransport transport) {
    if (!docType.equals(DocumentDataParser.MDL_DOC_TYPE)) {
      throw new IllegalArgumentException("Invalid docType");
    }
    MDocDocument document = new MDocDocument(storageEngine, transport);
    document.mNumSigningKeys = numSigningKeys;
    document.mDocName = name;
    document.mDocType = docType;
    document.mSigningKeyMinValidDuration = signingKeyMinValidDuration;
    document.mApduHelper = new DirectAccessAPDUHelper();
    document.mCborHelper = new DirectAccessCborHelper();
    document.mSlot = document.getNextAvailableSlot();
    // TODO Remove below dummy code.
    long notBefore = System.currentTimeMillis();
    long notAfter = notBefore + CREDENTIAL_KEY_VALID_DURATION;
    // Create credential key
    byte[] apdu = null;
    byte[] response = null;
    try {
      document.selectProvisionApplet();
      apdu = document.mApduHelper.createCredentialAPDU(document.mSlot, challenge, notBefore, notAfter);
      response = document.mTransport.sendData(apdu);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to send createCredential APDU command");
    }
    List<X509Certificate> credentialKeyCert = document.mCborHelper.decodeCredentialKeyResponse(response);
    List<PresentationPackage> presentationPackages = document.createPresentationPackage(
        document.mSlot);
    document.saveCredentialKeyCert(name, docType, numSigningKeys,
        credentialKeyCert);
    document.savePresentationPackage(presentationPackages);
    return document;
  }

  private int getNextAvailableSlot() {
    // Currently Applet supports only one slot.
    return SLOT_0;
  }

  private List<PresentationPackage> createPresentationPackage(int slot) {
    byte[] response = null;
    List<PresentationPackage> presentationPackages = new ArrayList<>();
    try {
      for (int i = 0; i < mNumSigningKeys; i++) {
        byte[] apdu = mApduHelper.createPresentationPackageAPDU(slot, mSigningKeyMinValidDuration);
        response = mTransport.sendData(apdu);
        // Decode presentation package.
        presentationPackages.add(mCborHelper.decodePresentationPackage(response));
      }
    } catch (IOException e) {
      Logger.d(TAG, "Failed to create presentation package");
      throw new IllegalStateException("Failed to create presentation package", e);
    }
    return presentationPackages;
  }

  public static MDocDocument lookupDocument(@NonNull String name,
                                            @NonNull StorageEngine storageEngine, @NonNull DirectAccessTransport transport) {
    MDocDocument credential = new MDocDocument(storageEngine, transport);
    credential.mDocName = name;
    Logger.d(TAG, "lookupDocument");
    CborMap map = credential.parseSavedCredential();
    if (map == null) {
      return null;
    }
    DataItem numSigningKeysDataItem = map.get("numSigningKeys");
    if (numSigningKeysDataItem != null) {
      credential.mNumSigningKeys = (int) numSigningKeysDataItem.getAsNumber();
    }
    DataItem docTypeItem = map.get("docType");
    if (docTypeItem != null) {
      credential.mDocType = docTypeItem.getAsTstr();
    }
    DataItem minValidDurationItem = map.get("signingKeyMinValidDuration");
    if (minValidDurationItem != null) {
      long milliseconds = (int) minValidDurationItem.getAsNumber();
      credential.mSigningKeyMinValidDuration = Duration.ofMillis(milliseconds);
    }
    credential.mApduHelper = new DirectAccessAPDUHelper();
    credential.mCborHelper = new DirectAccessCborHelper();
    credential.mSlot = credential.getNextAvailableSlot();
    return credential;
  }

  private boolean isSigningKeyCertReqeustProvisioned(MDocSigningKeyCertificationRequest request) {
    CborMap map = parsePresentationPackage();
    if (map == null) {
      return false;
    }
    DataItem ppItem = map.get("presentationPackage");
    List<DataItem> mapItems = ppItem.getAsArray();
    for (DataItem item : mapItems) {
      X509Certificate cert = getSigningKeyCert(item);
      if (request.getCertificate().equals(cert)) {
        return item.getOrNull("provisionedSlot") != null;
      }
    }
    return false;
  }

  private void saveEncryptedDataPresentationPackage(MDocSigningKeyCertificationRequest request,
      byte[] encryptedData, Instant expirationDate) {
    CborMap map = parsePresentationPackage();
    if (map == null) {
      throw new IllegalStateException("No Data found for doc name: " + mDocName);
    }
    List<DataItem> ppItems = map.get("presentationPackage").getAsArray();
    for (int i = 0; i < ppItems.size(); i++) {
      DataItem ppItem = ppItems.get(i);
      X509Certificate cert = getSigningKeyCert(ppItem);
      if (request.getCertificate().equals(cert)) {
        CborMap ppItemMap = new CborMap(ppItem.getAsMap(), false);
        MapBuilder<CborBuilder> newMap = CborMap.Companion.builder();
        for (DataItem existingKey: ppItemMap.getItems().keySet())
        {
          newMap.put(existingKey, ppItemMap.get(existingKey));
        }

        newMap.put("encryptedData", encryptedData)
                .put("expirationDate", expirationDate.getEpochSecond())
                .put("provisionedSlot", SLOT_0);
        ppItems.set(i, newMap.end().build());
        break;
      }
    }
    mStorageEngine.delete(MDOC_PREFIX + mDocName);
    mStorageEngine.put(MDOC_PREFIX + mDocName,
            Cbor.encode(map));
  }

  private void savePresentationPackage( @NonNull List<PresentationPackage> presentationPackages) {
    MapBuilder<CborBuilder> map = CborMap.Companion.builder();
    ArrayBuilder<MapBuilder<CborBuilder>> authKeysBuilder = map.putArray("presentationPackage");
    for (PresentationPackage presentationPackage : presentationPackages) {
      MapBuilder<ArrayBuilder<MapBuilder<CborBuilder>>> presentationPackageMap = authKeysBuilder.addMap();
      presentationPackageMap.put("usageCount", 0);
      ArrayBuilder<MapBuilder<ArrayBuilder<MapBuilder<CborBuilder>>>> signCertBuilder = presentationPackageMap.putArray(
          "authenticationKeys");
      for (X509Certificate certificate : presentationPackage.signingCert) {
        try {
          signCertBuilder.add(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
          throw new IllegalStateException("Error encoding certificate chain", e);
        }
      }
      signCertBuilder.end();
      presentationPackageMap.put("encryptedData", presentationPackage.encryptedData);
      presentationPackageMap.end();
    }
    authKeysBuilder.end();
    mStorageEngine.put(MDOC_PREFIX + mDocName,
        Cbor.encode(map.end().build()));
  }

  private void saveCredentialKeyCert(@NonNull String name, @NonNull String docType,
      int numSigningKeys,
      List<X509Certificate> credCert) {
    MapBuilder<CborBuilder> map = CborMap.Companion.builder();
    map.put("docType", mDocType);
    map.put("signingKeyMinValidDuration", mSigningKeyMinValidDuration.toMillis());
    map.put("numSigningKeys", numSigningKeys);
    ArrayBuilder<MapBuilder<CborBuilder>> attestationBuilder = map.putArray("attestation");
    for (X509Certificate certificate : credCert) {
      try {
        attestationBuilder.add(certificate.getEncoded());
      } catch (CertificateEncodingException e) {
        throw new IllegalStateException("Error encoding certificate chain", e);
      }
    }
    attestationBuilder.end();
    mStorageEngine.put(MDOC_CREDENTIAL_PREFIX + mDocName,
        Cbor.encode(map.end().build()));
  }

  private CborMap parseStoredData(@NonNull String path) {
    byte[] data = mStorageEngine.get(path);
    if (data == null) {
      Logger.e(TAG, "No Data found for doc name: "+ mDocName);
      return null;
    }
    Map<DataItem, DataItem> dataItems;
    try {
      dataItems = Cbor.decode(data).getAsMap();
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException("Error decoded CBOR", e);
    }

    return new CborMap(dataItems, false);
  }

  private CborMap parseSavedCredential() {
    return parseStoredData(MDOC_CREDENTIAL_PREFIX + mDocName);
  }

  private CborMap parsePresentationPackage() {
    return parseStoredData(MDOC_PREFIX + mDocName);
  }

  // Gets the certificate chain and attestation for CredentialKey. The
  // `challenge` parameter passed to createCredential() is included
  // in the Android attestation extension. CredentialKey is not a KeyMint
  // key but it uses the same style of attestation.
  //
  public List<X509Certificate> getCredentialKeyCertificateChain() {
    CborMap map = parseSavedCredential();
    if (map == null) {
      return null;
    }
    List<DataItem> attestationDataItems = map.get("attestation").getAsArray();
    List<X509Certificate> attestation = new ArrayList<>();
    for (DataItem item : attestationDataItems) {
      byte[] encodedCert = item.getAsBstr();
      try {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream certBais = new ByteArrayInputStream(encodedCert);
        attestation.add((X509Certificate) cf.generateCertificate(certBais));
      } catch (CertificateException e) {
        throw new IllegalStateException("Error decoding certificate blob", e);
      }
    }
    return attestation;
  }

  // Gets the number of signing keys for the credential, this is the same
  // same as the `numSigningKeys` parameter passed to createMDocCredential().
  //
  public int getNumSigningKeys() {
    CborMap map = parseSavedCredential();
    if (map == null) {
      return 0;
    }
    DataItem numSigningKeysDataItem = map.get("numSigningKeys");
    return (int) numSigningKeysDataItem.getAsNumber();
  }

  // Gets the duration a signing key must still be valid for until a
  // replacement will be requested. This is the same as the parameter
  // `signingKeyMinValidDuration` passed to createMDocCredential().
  //
  public Duration getSigningKeyMinValidDuration() {
    CborMap map = parseSavedCredential();
    if (map == null) {
      return null;
    }
    DataItem signingKeyMinValidDuration = map.get("signingKeyMinValidDuration");
    long duration = signingKeyMinValidDuration.getAsNumber();
    return Duration.ofMillis(duration);
  }

  // Returns information about signing keys for the credential.
  //
  // The returned list is always `numSigningKeys` elements long but may
  // contains nulls if the signing key hasn't been provisioned yet.
  //
  public List<MDocSigningKeyMetadata> getSigningKeysMetadata() {
    CborMap map = parsePresentationPackage();
    if (map == null) {
      return null;
    }
    DataItem ppItem = map.get("presentationPackage");
    List<DataItem> mapItems = ppItem.getAsArray();
    List<MDocSigningKeyMetadata> metadataList = new ArrayList<>();
    for (DataItem item : mapItems) {
      MDocSigningKeyMetadata metadata = new MDocSigningKeyMetadata();
      CborMap mapEntry = new CborMap(item.getAsMap(), false);
      DataItem usageCountItem = mapEntry.get("usageCount");
      int usageCount = (int) usageCountItem.getAsNumber();
      DataItem expiryDateItem = mapEntry.getOrNull("ExpiryDate"); // TODO never put into presentationPackage?
      metadata.mUsageCount = usageCount;
      metadata.mExpirationDate = null;
      if (expiryDateItem != null) {
        long expiryDate = expiryDateItem.getAsNumber();
        metadata.mExpirationDate = Instant.ofEpochMilli(expiryDate);
      }
      metadataList.add(metadata);
    }
    return metadataList;
  }

  // Clears all signing keys and associated data.
  //
  // This should be used when PII in a credential is updated.
  //
  public void clearAllSigningKeys() {
    mStorageEngine.delete(MDOC_PREFIX + mDocName);
  }

  private byte[] getEncryptedDataPresentationPackage(MDocSigningKeyCertificationRequest request) {
    CborMap map = parsePresentationPackage();
    if (map == null) {
      return null;
    }
    DataItem ppItem = map.get("presentationPackage");
    List<DataItem> mapItems = ppItem.getAsArray();
    for (DataItem item : mapItems) {
      X509Certificate cert = getSigningKeyCert(item);
      if (request.getCertificate().equals(cert)) {
        DataItem encryptedDataItem = new CborMap(item.getAsMap(), false).get("encryptedData");
        return encryptedDataItem.getAsBstr();
      }
    }
    return null;
  }

  private X509Certificate getSigningKeyCert(DataItem presentationPackageItem) {
    CborMap mapEntry = new CborMap(presentationPackageItem.getAsMap(), false);
    Logger.d(TAG, mapEntry.getItems().toString());
    DataItem authenticationKeys = mapEntry.get("authenticationKeys");
    List<DataItem> dataItems = authenticationKeys.getAsArray();
    DataItem leafCertItem = dataItems.get(0); // Leaf
    byte[] certData = leafCertItem.getAsBstr();
    X509Certificate cert = null;
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream bis = new ByteArrayInputStream(certData);
      cert = ((X509Certificate) cf.generateCertificate(bis));
    } catch (CertificateException e) {
      throw new IllegalStateException("Error generating certificate from response", e);
    }
    return cert;
  }

  // Gets all pending requests to have signing keys certified.
  //
  // This includes replacement signing keys for keys that are still valid but
  // are about to expire soon that is, inside the window returned by
  // getSigningKeyMinValidTimeMillis().
  //
  public List<MDocSigningKeyCertificationRequest> getSigningKeyCertificationRequests(
      Duration validityPeriod) {
    CborMap map = parsePresentationPackage();
    DataItem ppItem = map.get("presentationPackage");
    List<DataItem> mapItems = ppItem.getAsArray();
    List<MDocSigningKeyCertificationRequest> certificationRequests = new ArrayList<>();
    for (DataItem item : mapItems) {
      MDocSigningKeyCertificationRequest certificationRequest =
          new MDocSigningKeyCertificationRequest();
      X509Certificate cert = getSigningKeyCert(item);
      try {
        cert.checkValidity(Date.from(Instant.now().plus(validityPeriod)));
      } catch (CertificateExpiredException | CertificateNotYetValidException e) {
        continue;
      }
      certificationRequest.mSigningCertificate = cert;
      certificationRequests.add(certificationRequest);
    }
    return certificationRequests;
  }

  private byte[] sendApdu(int cmd, int slot, byte[] data, int offset, int length, byte operation) throws IOException {
    byte[] beginApdu = mApduHelper.createProvisionSwapInApdu(cmd, slot,
        data, offset, length, operation);
    byte[] response = mTransport.sendData(beginApdu);
    return mCborHelper.decodeProvisionResponse(response);
  }

  private byte[] provision(int slot, byte[] data, int offset, int length, byte operation) throws IOException {
    return sendApdu(DirectAccessAPDUHelper.CMD_MDOC_PROVISION_DATA, slot, data, offset, length, operation);
  }

  private byte[] swapIn(int slot, byte[] data, int offset, int length, byte operation) throws IOException {
    return sendApdu(DirectAccessAPDUHelper.CMD_MDOC_SWAP_IN, slot, data, offset, length, operation);
  }

  // Provisions credential data for a specific signing key request.
  //
  // The |credentialData| parameter must be CBOR conforming to the following CDDL:
  //
  //   CredentialData = {
  //     "docType": tstr,
  //     "issuerNameSpaces": IssuerNameSpaces,
  //     "issuerAuth" : IssuerAuth,
  //     "readerAccess" : ReaderAccess
  //   }
  //
  //   IssuerNameSpaces = {
  //     NameSpace => [ + IssuerSignedItemBytes ]
  //   }
  //
  //   ReaderAccess = [ * COSE_Key ]
  //
  // This data will stored on the Secure Area and used for MDOC presentations
  // using NFC data transfer in low-power mode.
  //
  // The `readerAccess` field contains a list of keys used for implementing
  // reader authentication. If this list is non-empty, reader authentication
  // is not required. Otherwise the request must be be signed and the request is
  // authenticated if, and only if, a public keys from the X.509 certificate
  // chain for the key signing the request exists in the `readerAccess` list.
  //
  // If reader authentication fails, the returned DeviceResponse shall return
  // error code 10 for the requested docType in the "documentErrors" field.
  //
  public void provision(MDocSigningKeyCertificationRequest request, Instant expirationDate,
      byte[] credentialData) {
    selectProvisionApplet();
    DocumentDataParser.validateCredentialData(credentialData);
    ByteArrayOutputStream bao = new ByteArrayOutputStream();
    try {
      // BEGIN
      byte[] encryptedData = getEncryptedDataPresentationPackage(request);
      bao.write(provision(SLOT_0,
          encryptedData, 0, encryptedData.length, PROVISION_BEGIN));

      // UPDATE
      byte[] encodedCredData = Cbor.encode(new Bstr(credentialData));
      int remaining = encodedCredData.length;
      int start = 0;
      int maxTransmitBufSize = 512;
      while(remaining > maxTransmitBufSize) {
        bao.write(provision(SLOT_0,
            encodedCredData, start, maxTransmitBufSize, PROVISION_UPDATE));
        start += maxTransmitBufSize;
        remaining -= maxTransmitBufSize;
      }

      // Finish
      bao.write(provision(SLOT_0,
          encodedCredData, start, remaining, PROVISION_FINISH));
    } catch (IOException e) {
      throw new IllegalStateException("Failed to provision credential data "+e);
    }
    saveEncryptedDataPresentationPackage(request, bao.toByteArray(), expirationDate);
  }

  public void swapIn(MDocSigningKeyCertificationRequest request) {
    try {
      selectProvisionApplet();
      byte[] encryptedData = getEncryptedDataPresentationPackage(request);
      int remaining = encryptedData.length;
      int start = 0;
      int maxTransmitBufSize = 512;
      // BEGIN
      swapIn(SLOT_0,
          encryptedData, 0, maxTransmitBufSize, PROVISION_BEGIN);
      start += maxTransmitBufSize;
      remaining -= maxTransmitBufSize;

      // UPDATE
      while(remaining > maxTransmitBufSize) {
        swapIn(SLOT_0,
            encryptedData, start, maxTransmitBufSize, PROVISION_UPDATE);
        start += maxTransmitBufSize;
        remaining -= maxTransmitBufSize;
      }

      // Finish
      swapIn(SLOT_0,
          encryptedData, start, remaining, PROVISION_FINISH);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to provision credential data "+e);
    }
  }

  public static class MDocSigningKeyCertificationRequest {
    private X509Certificate mSigningCertificate;

    static MDocSigningKeyCertificationRequest create(X509Certificate signingCertificate) {
      MDocSigningKeyCertificationRequest certificationRequest = new MDocSigningKeyCertificationRequest();
      certificationRequest.mSigningCertificate = signingCertificate;
      return certificationRequest;
    }

    public X509Certificate getCertificate() {
      return mSigningCertificate;
    }
  }

  public static class MDocSigningKeyMetadata {

    private int mUsageCount;
    private Instant mExpirationDate;

    static MDocSigningKeyMetadata create(int usageCount, Instant expirationDate) {
      MDocSigningKeyMetadata metadata = new MDocSigningKeyMetadata();
      metadata.mUsageCount = usageCount;
      metadata.mExpirationDate = expirationDate;
      return metadata;
    }

    // Returns how many times the signing key has been used.
    //
    public int getUsageCount() {
      return mUsageCount;
    }

    // Returns the expiration date which was passed to the provision() call
    // when the signing key was certified.
    //
    public Instant getExpirationDate() {
      return mExpirationDate;
    }


  }

  void deleteCredential() {
    try {
      selectProvisionApplet();
      byte[] apdu = mApduHelper.deleteMDocAPDU(mSlot);
      byte[] response = mTransport.sendData(apdu);
      mCborHelper.decodeDeleteCredential(response);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to delete MDoc");
    }

    mStorageEngine.delete( MDOC_CREDENTIAL_PREFIX + mDocName);
    mStorageEngine.delete( MDOC_PREFIX + mDocName);
  }
}
