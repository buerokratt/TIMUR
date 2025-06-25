package ee.eesti.authentication.enums;

/**
 * Each language enumeration contains a private field with associated uri.
 * When extending this enumeration ensure that uri-s are indeed unique.
 */
public enum Language {
	EE("/est/"),
	EN("/eng/"),
	RU("/rus/");

	private final String uri;

	Language(String uri) {
		this.uri = uri;
	}

	/**
	 * @return uri for this Language
	 */
	public String getUri() {
		return this.uri;
	}

	/**
	 *
	 * @param uri to search Language by
	 * @return Language associated with this uri
	 */
	public static Language getByUri(String uri) {
		if (uri == null) {
			return EE;
		}
		for (Language language : Language.values()) {
			if (uri.contains(language.getUri())) {
				return language;
			}
		}
		return EE;
	}
}
