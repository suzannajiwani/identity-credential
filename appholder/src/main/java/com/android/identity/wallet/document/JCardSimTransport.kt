package com.android.identity.wallet.document

import com.android.identity.android.direct_access.DirectAccessSmartCardTransport
import com.android.identity.direct_access.DirectAccessTransport

object JCardSimTransport {
  fun instance(): DirectAccessTransport {
    return Loader.mTransport
  }

  private object Loader {
    val mTransport = DirectAccessSmartCardTransport()
  }
}