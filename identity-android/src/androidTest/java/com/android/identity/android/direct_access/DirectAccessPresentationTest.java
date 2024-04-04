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
import androidx.test.ext.junit.runners.AndroidJUnit4;
import com.android.identity.android.mdoc.deviceretrieval.IsoDepWrapper;
import com.android.identity.android.mdoc.deviceretrieval.VerificationHelper;
import com.android.identity.android.mdoc.transport.DataTransportOptions;
import com.android.identity.crypto.CertificateChain;
import com.android.identity.mdoc.connectionmethod.ConnectionMethod;
import com.android.identity.mdoc.response.DeviceResponseParser;
import com.android.identity.util.Constants;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class DirectAccessPresentationTest extends DirectAccessTest {
  private static final String TAG = "DirectAccessPresentationTest";

  private static final int DEVICE_CONNECT_STATUS_DISCONNECTED = 0;

  private static final int DEVICE_CONNECT_STATUS_CONNECTED = 1;
  private int mDeviceConnectStatus;
  private Throwable mError;
  private CountDownLatch mCountDownLatch;
  private VerificationHelper mVerificationHelper;
  private List<ConnectionMethod> mConnectionMethods;

  private byte[] mDeviceResponse;

  private static final String[] entries = {"sex", "portrait", "given_name", "issue_date",
  "expiry_date", "family_name", "document_number", "issuing_authority"};

  @Before
  public void init() {
    super.init(TransportType.SMARTCARDIO);
    mConnectionMethods = null;
    mDeviceConnectStatus = DEVICE_CONNECT_STATUS_DISCONNECTED;
    mError = null;
  }

  @Override
  @After
  public void reset() {
    super.reset();
  }

  VerificationHelper.Listener mResponseListener = new VerificationHelper.Listener() {

    @Override
    public void onDeviceEngagementReceived(@NonNull List<? extends ConnectionMethod> connectionMethods) {
      mConnectionMethods = ConnectionMethod.disambiguate(connectionMethods);
      mCountDownLatch.countDown();
    }

    @Override
    public void onReaderEngagementReady(@NonNull byte[] readerEngagement) {
    }

    @Override
    public void onMoveIntoNfcField() {
    }

    @Override
    public void onDeviceConnected() {
      mDeviceConnectStatus = DEVICE_CONNECT_STATUS_CONNECTED;
    }

    @Override
    public void onDeviceDisconnected(boolean transportSpecificTermination) {
      mDeviceConnectStatus = DEVICE_CONNECT_STATUS_DISCONNECTED;
      mCountDownLatch.countDown();
    }

    @Override
    public void onResponseReceived(@NonNull byte[] deviceResponseBytes) {
      mDeviceResponse = deviceResponseBytes;
      mCountDownLatch.countDown();
    }

    @Override
    public void onError(@NonNull Throwable error) {
      mError = error;
      mCountDownLatch.countDown();
    }
  };

  private DeviceResponseParser.DeviceResponse parseDeviceResponse(byte[] deviceResponse) {
    DeviceResponseParser parser = new DeviceResponseParser(deviceResponse, mVerificationHelper.getSessionTranscript());
    parser.setEphemeralReaderKey(mVerificationHelper.getEReaderKey());
    return parser.parse();
  }

  private void resetLatch() {
    mCountDownLatch = new CountDownLatch(1);
  }

  private void waitForResponse(int expectedDeviceConnectionStatus) {
    try {
      mCountDownLatch.await();
    } catch (InterruptedException e) {
      // do nothing
    }
    checkSessionStatus(expectedDeviceConnectionStatus);
  }

  private void checkSessionStatus(int expectedDeviceStatus) {
    Assert.assertEquals("Device connection status ", expectedDeviceStatus, mDeviceConnectStatus);
    if (mError != null) {
      Assert.fail(mError.getMessage());
    }
  }

  private void generateReaderCerts(boolean isSelfSigned) {
    try {
      KeyPair keyPair = new DirectAccessTestUtils().generateReaderKeyPair();
      CertificateChain readerCertChain =
          new DirectAccessTestUtils().getReaderCertificateChain(mContext, keyPair, isSelfSigned);
      mReaderKeys = new ArrayList<>();
      mReaderKeys.add(keyPair);

      mReaderCertChain = new HashMap<>();
      mReaderCertChain.put(keyPair, readerCertChain);
    } catch (Exception e) {
      Assert.fail(e.getMessage());
    }
  }

  @Test
  public void testPresentation() {
    generateReaderCerts(true);
    provisionAndSwapIn();
    VerificationHelper.Builder builder = new VerificationHelper.Builder(mContext, mResponseListener,
        mContext.getMainExecutor());
    DataTransportOptions options = new DataTransportOptions.Builder().setBleClearCache(false)
        .setBleClearCache(false).build();
    builder.setDataTransportOptions(options);
    mVerificationHelper = builder.build();

    IsoDepWrapper wrapper = new ShadowIsoDep(mTransport);
    resetLatch();
    mVerificationHelper.mockTagDiscovered(wrapper);
    // Wait till the device engagement is received.
    waitForResponse(DEVICE_CONNECT_STATUS_DISCONNECTED);
    Assert.assertNotNull(mConnectionMethods);
    Assert.assertTrue(mConnectionMethods.size() > 0);
    mVerificationHelper.connect(mConnectionMethods.get(0));
    byte[] devReq = null;
    try {
      KeyPair readerKeypair = null;
      CertificateChain certChain = null;
      if (mReaderKeys != null) {
        readerKeypair = mReaderKeys.get(0);
        certChain = mReaderCertChain.get(mReaderKeys.get(0));
      }
      devReq = new DirectAccessTestUtils().createMdocRequest(readerKeypair,
          certChain,
          entries,
          mVerificationHelper.getSessionTranscript());
    } catch (Exception e) {
      Assert.fail(e.getMessage());
    }
    resetLatch();
    mVerificationHelper.sendRequest(devReq);
    // Wait till the mdoc response is received.
    waitForResponse(DEVICE_CONNECT_STATUS_CONNECTED);
    Assert.assertNotNull(mDeviceResponse);
    DeviceResponseParser.DeviceResponse dr = parseDeviceResponse(mDeviceResponse);
    Assert.assertNotNull(dr);
    Assert.assertEquals(Constants.DEVICE_RESPONSE_STATUS_OK, dr.getStatus());
    new DirectAccessTestUtils().validateMdocResponse(dr, entries);
    resetLatch();
    mVerificationHelper.disconnect();
  }
}
