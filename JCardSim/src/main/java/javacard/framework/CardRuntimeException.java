package javacard.framework;

public class CardRuntimeException extends RuntimeException{
  private short reason;

  /**
   * Constructs a CardRuntimeException instance with the specified reason.
   * To conserve on resources, use the <code>throwIt()</code> method
   * to employ the Java Card runtime environment-owned instance of this class.
   * @param reason the reason for the exception
   */
  public CardRuntimeException(short reason) {
    this.reason = reason;
  }

  /**
   * Get reason code
   * @return the reason for the exception
   */
  public short getReason() {
    return reason;
  }

  /**
   * Set reason code
   * @param reason the reason for the exception
   */
  public void setReason(short reason) {
    this.reason = reason;
  }

  /**
   * Throws the Java Card runtime environment-owned instance of the <code>CardRuntimeException</code> class with the
   * specified reason.
   * <p>Java Card runtime environment-owned instances of exception classes are temporary Java Card runtime environment Entry Point Objects
   * and can be accessed from any applet context. References to these temporary objects
   * cannot be stored in class variables or instance variables or array components.
   * See <em>Runtime Environment Specification for the Java Card Platform</em>, section 6.2.1 for details.
   * @param reason the reason for the exception
   * @throws CardRuntimeException always
   */
  public static void throwIt(short reason)
      throws CardRuntimeException {
    throw new CardRuntimeException(reason);
  }
}