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

import android.content.Context;
import android.se.omapi.SEService;
import android.se.omapi.SEService.OnConnectedListener;
import android.util.Log;

import androidx.test.platform.app.InstrumentationRegistry;
import com.android.identity.android.storage.AndroidStorageEngine;
import com.android.identity.crypto.Certificate;
import com.android.identity.crypto.CertificateChain;
import com.android.identity.storage.StorageEngine;
import com.android.identity.util.Logger;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeoutException;
import org.junit.Assert;

public abstract class DirectAccessTest {
  private static final String TAG = "DirectAccessTest";

  public enum TransportType {OMAPI, SOCKET, SMARTCARDIO};
  private static TransportType mTransType = TransportType.OMAPI;
  private final long SERVICE_CONNECTION_TIME_OUT = 3000;
  private Object serviceMutex = new Object();
  private boolean connected = false;
  private Timer connectionTimer;
  private ServiceConnectionTimerTask mTimerTask = new ServiceConnectionTimerTask();
  private SEService mSEService;
  protected DirectAccessTransport mTransport;
  protected MDocStore mDocStore;
  protected String mDocName;
  protected StorageEngine mStorageEngine;
  protected Context mContext;

  protected ArrayList<KeyPair> mReaderKeys;
  protected HashMap<KeyPair, CertificateChain> mReaderCertChain;
  public static void setTransportType(TransportType t){
    mTransType = t;
  }
  private final OnConnectedListener mListener = new OnConnectedListener() {
    public void onConnected() {
      synchronized (serviceMutex) {
        connected = true;
        serviceMutex.notify();
      }
    }
  };

  class SynchronousExecutor implements Executor {

    public void execute(Runnable r) {
      r.run();
    }
  }

  class ServiceConnectionTimerTask extends TimerTask {

    @Override
    public void run() {
      synchronized (serviceMutex) {
        serviceMutex.notifyAll();
      }
    }
  }

  protected void waitForConnection() throws TimeoutException {
    if (mTransport instanceof DirectAccessSocketTransport ||
    mTransport instanceof DirectAccessSmartCardTransport) {
      return;
    }
    synchronized (serviceMutex) {
      if (!connected) {
        try {
          serviceMutex.wait();
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
      if (!connected) {
        throw new TimeoutException(
            "Service could not be connected after " + SERVICE_CONNECTION_TIME_OUT + " ms");
      }
      if (connectionTimer != null) {
        connectionTimer.cancel();
      }
    }
  }

  protected DirectAccessTransport getDirectAccessTransport(TransportType transType) {
    switch (transType){
      case SOCKET:
        return new DirectAccessSocketTransport();
      case OMAPI:
        return new DirectAccessOmapiTransport(mSEService);
      case SMARTCARDIO:
        return new DirectAccessSmartCardTransport();
      default:
        return null;
    }
  }

  protected void init(){
    init(mTransType);
  }
  protected void init(TransportType type) {
    mTransType = type;
    mContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
    mSEService = new SEService(mContext, new SynchronousExecutor(), mListener);
    File storageDir = new File(mContext.getDataDir(), "ic-testing");
    mStorageEngine = new AndroidStorageEngine.Builder(mContext, storageDir).build();
    connectionTimer = new Timer();
    connectionTimer.schedule(mTimerTask, SERVICE_CONNECTION_TIME_OUT);
    mTransport = getDirectAccessTransport(type);
    try {
      mTransport.init();
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  protected void reset() {
    if (mDocStore != null) {
      Logger.d(TAG, "reset");
      mDocStore.deleteDocument(mDocName);
      mDocStore = null;
    }
    try {
      if (mTransport != null) {
        mTransport.closeConnection();
        mTransport.unInit();
        mTransport = null;
      }
    } catch (IOException e) {
      fail("Unexpected Exception " + e);
    }
  }

  protected void provisionAndSwapIn() {
    mDocName = "mDL";
    byte[] challenge = "challenge".getBytes();
    int numSigningKeys = 0;
    MDocDocument credential = null;
    try {
      waitForConnection();

      numSigningKeys = 1;
      mDocStore = new MDocStore(mTransport, mStorageEngine);
      credential = mDocStore.createDocument(mDocName,
          DocumentDataParser.MDL_DOC_TYPE, challenge, numSigningKeys, Duration.ofDays(365));
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
      ArrayList<Certificate> cert = null;
      if (mReaderCertChain != null) {
        cert = new ArrayList<>();
        for(Map.Entry<KeyPair, CertificateChain> entry : mReaderCertChain.entrySet()) {
          KeyPair key = entry.getKey();
          CertificateChain certChain = entry.getValue();

          if (certChain != null && certChain.getCertificates().size() > 0) {
            cert.add(certChain.getCertificates().get(0)); // Add leaf public key
          }
        }
      }
      byte[] encodedCredData = new DirectAccessTestUtils().createCredentialData(mContext,
          certificationRequests.get(0), DocumentDataParser.MDL_DOC_TYPE, cert);
      credential.provision(certificationRequests.get(0), Instant.now(), encodedCredData);
      // Set data
      credential.swapIn(certificationRequests.get(0));
  }
}
