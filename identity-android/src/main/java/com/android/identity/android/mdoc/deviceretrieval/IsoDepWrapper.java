package com.android.identity.android.mdoc.deviceretrieval;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import java.io.IOException;

public interface IsoDepWrapper {

  public Tag getTag();

  public void getIsoDep(Tag tag);

  public boolean isConnected();

  public void connect() throws IOException;


  public void close() throws IOException;

  boolean isTagSupported();

  public void setTimeout(int timeout);
  public int getTimeout();

  public byte[] getHistoricalBytes();

  public byte[] getHiLayerResponse();

  public int getMaxTransceiveLength();

  public byte[] transceive(byte[] data) throws IOException;

  public boolean isExtendedLengthApduSupported();

}
