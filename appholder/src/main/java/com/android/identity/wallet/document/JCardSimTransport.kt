package com.android.identity.wallet.document

import com.android.identity.android.direct_access.DirectAccessSmartCardTransport

object JCardSimTransport {
  fun instance(): DirectAccessTransport {
    return Loader.mTransport
  }

  private object Loader {
    val mTransport = DirectAccessSmartCardTransport()
  }
}