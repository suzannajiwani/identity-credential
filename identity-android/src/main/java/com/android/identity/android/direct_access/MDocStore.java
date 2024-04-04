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
import androidx.annotation.Nullable;
import com.android.identity.storage.StorageEngine;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class MDocStore {
  private static final String TAG = "MDocStore";
  private final StorageEngine mStorageEngine;
  private final  DirectAccessTransport mTransport;
  private static final boolean TEST = true;

  public MDocStore(@NonNull DirectAccessTransport transport,
      @NonNull StorageEngine storageEngine) throws IOException {
    this.mStorageEngine = storageEngine;
    this.mTransport = transport;
    // open the connection.
    mTransport.openConnection();
  }

  // Creates a new MDOC credential with the given name and DocType.
  //
  // The challenge must not be longer than XX bytes.
  //
  // Throws Doctype AlreadyExists if a credential with the given DocType
  // already exists for Direct Access.
  //
  // Throws MaxNumberOfCredentialsReached if there is not enough room in
  // Secure Hardware.
  //
  public MDocDocument createDocument(
      String name,
      String docType,
      byte[] challenge,
      int numSigningKeys,
      Duration signingKeyMinValidDuration) throws IOException, CertificateException {
    return MDocDocument.create(name, docType, challenge, numSigningKeys, signingKeyMinValidDuration,
        mStorageEngine, mTransport);
  }

  // Looks up a MDOC credential previously created with createMDocCredential().
  //
  // Returns `null` if no such credential exists.
  //
  @Nullable
  public MDocDocument lookupDocument(String name) {
    return MDocDocument.lookupDocument(name, mStorageEngine, mTransport);
  }

  // Looks up for all the list credential names.
  //
  // Returns list of credential names.
  public @NonNull List<String> listDocuments() {
    ArrayList<String> ret = new ArrayList<>();
    for (String name : mStorageEngine.enumerate()) {
      if (name.startsWith(MDocDocument.MDOC_CREDENTIAL_PREFIX)) {
        ret.add(name.substring(MDocDocument.MDOC_CREDENTIAL_PREFIX.length()));
      }
    }
    return ret;
  }

  // Gets the maximum size of credentialData which can be used for credentials.
  // This is guaranteed to be at least 32 KiB.
  //
  // Applications can communicate this value to the issuer to ensure that the
  // data they provision will fit in Secure Hardware.
  //
  long getMaximumCredentialDataSize() {
    return 0;
  }

  // Delete the credential with the provided name
  public void deleteDocument(@NonNull String name) {
    MDocDocument credential = MDocDocument.lookupDocument(name, mStorageEngine, mTransport);
    if (credential == null) {
      return;
    }
    credential.deleteCredential();
  }
}
