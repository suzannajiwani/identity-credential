package com.android.identity.android.mdoc.deviceretrieval;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import java.io.IOException;

public class IsoDepWrapperImpl implements IsoDepWrapper {
  private IsoDep mIsoDep;

  public IsoDepWrapperImpl(Tag tag) {
    mIsoDep = IsoDep.get(tag);
  }

  @Override
  public Tag getTag() {
    return mIsoDep.getTag();
  }

  @Override
  public boolean isConnected() {
    return mIsoDep.isConnected();
  }

  @Override
  public void connect() throws IOException {
    mIsoDep.connect();
  }

  @Override
  public void close() throws IOException {
    mIsoDep.close();
  }

  @Override
  public void getIsoDep(Tag tag) {
    mIsoDep = IsoDep.get(tag);
  }

  @Override
  public boolean isTagSupported() {
    return mIsoDep != null;
  }

  @Override
  public void setTimeout(int timeout) {
    mIsoDep.setTimeout(timeout);
  }

  @Override
  public int getTimeout() {
    return mIsoDep.getTimeout();
  }

  @Override
  public byte[] getHistoricalBytes() {
    return mIsoDep.getHistoricalBytes();
  }

  @Override
  public byte[] getHiLayerResponse() {
    return mIsoDep.getHiLayerResponse();
  }

  @Override
  public int getMaxTransceiveLength() {
    return 16384;//mIsoDep.getMaxTransceiveLength();
  }

  @Override
  public byte[] transceive(byte[] data) throws IOException {
    return mIsoDep.transceive(data);
  }

  @Override
  public boolean isExtendedLengthApduSupported() {
    return mIsoDep.isExtendedLengthApduSupported();
  }
}
