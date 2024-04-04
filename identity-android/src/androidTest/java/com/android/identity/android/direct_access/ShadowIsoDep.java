package com.android.identity.android.direct_access;

import android.nfc.Tag;
import com.android.identity.android.mdoc.deviceretrieval.IsoDepWrapper;
import java.io.IOException;

public class ShadowIsoDep implements IsoDepWrapper {

  public static String TECH_ISO_DEP = "android.nfc.tech.IsoDep";

  private DirectAccessTransport mTransport;
  private int mTimeout;

  public ShadowIsoDep(DirectAccessTransport transport) {
    mTransport = transport;
  }

  @Override
  public Tag getTag() {
    //android.nfc.tech.IsoDep
    //
    return null;
  }

  @Override
  public void getIsoDep(Tag tag) {
  }

  @Override
  public boolean isConnected() {
    try {
      return mTransport.isConnected();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void connect() throws IOException {
    mTransport.openConnection();
  }

  @Override
  public void close() throws IOException {
    mTransport.closeConnection();
  }

  @Override
  public boolean isTagSupported() {
    return true;
  }

  @Override
  public void setTimeout(int timeout) {
    mTimeout = timeout;
  }

  @Override
  public int getTimeout() {
    return mTimeout;
  }

  @Override
  public byte[] getHistoricalBytes() {
    return new byte[0];
  }

  @Override
  public byte[] getHiLayerResponse() {
    return new byte[0];
  }

  @Override
  public int getMaxTransceiveLength() {
    return mTransport.getMaxTransceiveLength();
  }

  @Override
  public byte[] transceive(byte[] data) throws IOException {
    return mTransport.sendData(data);
  }

  @Override
  public boolean isExtendedLengthApduSupported() {
    return true;
  }
}
