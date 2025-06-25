package ee.eesti.authentication.enums;
/**
 * Each ChannelType contains private fields for channel, loginlevel and amr.
 * As it is possible to search ChannelTypes by amr - the field values for amr must be unique.
 */
public enum ChannelType {
	AUTENTIMATA("AUTENTIMATA", "20", ""),
	ID("ID", "40", "idcard"),
	M_ID("M-ID", "40", "mID"),
	PANK("PANK", "30", "banklink"),
	EIDAS("eIDAS", "40", "eIDAS"),
  SMARTID("SMARTID", "40", "smartid"),
	DEFAULT("default", "40", "default")
	;

	private final String channel;
	private final String loginLevel;
	private final String amr;

	ChannelType(String channel, String loginLevel, String amr) {
		this.channel = channel;
		this.loginLevel = loginLevel;
		this.amr = amr;
	}

	public String getLoginLevel() {
		return this.loginLevel;
	}

	public String getChannel() {
		return this.channel;
	}

	public String getAmr() {
		return this.amr;
	}

	/**
	 * @param amr
	 * @return ChannelType that has the same unique amr
	 */
	public static ChannelType getByAmr(String amr) {
		for (ChannelType type : ChannelType.values()) {
			if (type.getAmr().equals(amr)) return type;
		}
		return null;
	}

  /**
   * @param channel
   * @return ChannelType that has the same unique channel
   */
  public static ChannelType getByChannel(String channel) {
    for (ChannelType type : ChannelType.values()) {
      if (type.getChannel().equals(channel)) return type;
    }
    return null;
  }
}
