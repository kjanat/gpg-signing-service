/**
 * IANA Media Types (MIME Types)
 *
 * Media types are grouped into top-level types:
 * - application: Binary data and application-specific formats
 * - audio: Audio content
 * - font: Font formats
 * - haptics: Haptic feedback data
 * - image: Image content
 * - message: Message encapsulation formats
 * - model: 3D model formats
 * - multipart: Composite content types
 * - text: Human-readable text content
 * - video: Video content
 *
 * Based on [IANA Media Types Registry](https://www.iana.org/assignments/media-types/media-types.xhtml)
 * @see [RFC 6838](https://www.rfc-editor.org/rfc/rfc6838) - Media Type Specifications and Registration Procedures
 * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046) - MIME Part Two: Media Types
 */
export enum MediaType {
  // ============================================================================
  // application/* - Binary data and application-specific formats
  // ============================================================================

  /**
   * **application/json**
   *
   * JavaScript Object Notation (JSON) data interchange format.
   * The standard format for REST APIs and data exchange.
   *
   * @see [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259)
   */
  ApplicationJson = "application/json",

  /**
   * **application/xml**
   *
   * Extensible Markup Language (XML) document.
   *
   * @see [RFC 7303](https://www.rfc-editor.org/rfc/rfc7303)
   */
  ApplicationXml = "application/xml",

  /**
   * **application/octet-stream**
   *
   * Arbitrary binary data. Used when the specific type is unknown
   * or when no other type is appropriate.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046)
   */
  ApplicationOctetStream = "application/octet-stream",

  /**
   * **application/pdf**
   *
   * Portable Document Format (PDF) document.
   *
   * @see [RFC 8118](https://www.rfc-editor.org/rfc/rfc8118)
   */
  ApplicationPdf = "application/pdf",

  /**
   * **application/zip**
   *
   * ZIP archive format. Note: Not in IANA registry but widely used.
   * Use application/octet-stream for strict IANA compliance.
   */
  ApplicationZip = "application/zip",

  /**
   * **application/gzip**
   *
   * GZIP compressed data.
   *
   * @see [RFC 6713](https://www.rfc-editor.org/rfc/rfc6713)
   */
  ApplicationGzip = "application/gzip",

  /**
   * **application/x-www-form-urlencoded**
   *
   * Form data encoded as key-value pairs. Standard encoding for HTML forms.
   */
  ApplicationFormUrlEncoded = "application/x-www-form-urlencoded",

  /**
   * **application/ld+json**
   *
   * JSON-LD (JSON for Linking Data) format for structured data.
   *
   * @see [W3C JSON-LD](https://www.w3.org/TR/json-ld/)
   */
  ApplicationLdJson = "application/ld+json",

  /**
   * **application/problem+json**
   *
   * Problem Details for HTTP APIs in JSON format.
   * Standard format for API error responses.
   *
   * @see [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)
   */
  ApplicationProblemJson = "application/problem+json",

  /**
   * **application/problem+xml**
   *
   * Problem Details for HTTP APIs in XML format.
   *
   * @see [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)
   */
  ApplicationProblemXml = "application/problem+xml",

  /**
   * **application/cbor**
   *
   * Concise Binary Object Representation (CBOR) data format.
   * A binary data serialization format based on JSON data model.
   *
   * @see [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949)
   */
  ApplicationCbor = "application/cbor",

  /**
   * **application/msgpack**
   *
   * MessagePack binary serialization format. Note: Not in IANA registry.
   */
  ApplicationMsgpack = "application/msgpack",

  /**
   * **application/protobuf**
   *
   * Protocol Buffers binary serialization format.
   *
   * @see [RFC draft-ietf-dispatch-mime-protobuf](https://datatracker.ietf.org/doc/draft-ietf-dispatch-mime-protobuf/)
   */
  ApplicationProtobuf = "application/protobuf",

  // --- Authentication & Security ---

  /**
   * **application/jwt**
   *
   * JSON Web Token (JWT) format.
   *
   * @see [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)
   */
  ApplicationJwt = "application/jwt",

  /**
   * **application/jwk+json**
   *
   * JSON Web Key (JWK) format.
   *
   * @see [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)
   */
  ApplicationJwkJson = "application/jwk+json",

  /**
   * **application/jwk-set+json**
   *
   * JSON Web Key Set (JWKS) format.
   *
   * @see [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)
   */
  ApplicationJwkSetJson = "application/jwk-set+json",

  /**
   * **application/jose**
   *
   * JOSE (JSON Object Signing and Encryption) compact serialization.
   *
   * @see [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)
   */
  ApplicationJose = "application/jose",

  /**
   * **application/jose+json**
   *
   * JOSE JSON serialization format.
   *
   * @see [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)
   */
  ApplicationJoseJson = "application/jose+json",

  /**
   * **application/cose**
   *
   * CBOR Object Signing and Encryption (COSE) format.
   *
   * @see [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)
   */
  ApplicationCose = "application/cose",

  /**
   * **application/cose-key**
   *
   * COSE Key format.
   *
   * @see [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)
   */
  ApplicationCoseKey = "application/cose-key",

  /**
   * **application/cose-key-set**
   *
   * COSE Key Set format.
   *
   * @see [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)
   */
  ApplicationCoseKeySet = "application/cose-key-set",

  // --- PGP/GPG ---

  /**
   * **application/pgp-encrypted**
   *
   * PGP encrypted data (version identifier part).
   *
   * @see [RFC 3156](https://www.rfc-editor.org/rfc/rfc3156)
   */
  ApplicationPgpEncrypted = "application/pgp-encrypted",

  /**
   * **application/pgp-signature**
   *
   * PGP digital signature.
   *
   * @see [RFC 3156](https://www.rfc-editor.org/rfc/rfc3156)
   */
  ApplicationPgpSignature = "application/pgp-signature",

  /**
   * **application/pgp-keys**
   *
   * PGP public keys.
   *
   * @see [RFC 3156](https://www.rfc-editor.org/rfc/rfc3156)
   */
  ApplicationPgpKeys = "application/pgp-keys",

  // --- PKI/Certificates ---

  /**
   * **application/pkcs7-mime**
   *
   * PKCS#7 MIME type for signed and/or encrypted data.
   *
   * @see [RFC 8551](https://www.rfc-editor.org/rfc/rfc8551)
   */
  ApplicationPkcs7Mime = "application/pkcs7-mime",

  /**
   * **application/pkcs7-signature**
   *
   * PKCS#7 detached signature.
   *
   * @see [RFC 8551](https://www.rfc-editor.org/rfc/rfc8551)
   */
  ApplicationPkcs7Signature = "application/pkcs7-signature",

  /**
   * **application/pkcs8**
   *
   * PKCS#8 private key format.
   *
   * @see [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958)
   */
  ApplicationPkcs8 = "application/pkcs8",

  /**
   * **application/pkcs10**
   *
   * PKCS#10 certificate signing request.
   *
   * @see [RFC 5967](https://www.rfc-editor.org/rfc/rfc5967)
   */
  ApplicationPkcs10 = "application/pkcs10",

  /**
   * **application/pkcs12**
   *
   * PKCS#12 personal information exchange format.
   */
  ApplicationPkcs12 = "application/pkcs12",

  /**
   * **application/pkix-cert**
   *
   * X.509 certificate in DER format.
   *
   * @see [RFC 2585](https://www.rfc-editor.org/rfc/rfc2585)
   */
  ApplicationPkixCert = "application/pkix-cert",

  /**
   * **application/pkix-crl**
   *
   * X.509 certificate revocation list in DER format.
   *
   * @see [RFC 2585](https://www.rfc-editor.org/rfc/rfc2585)
   */
  ApplicationPkixCrl = "application/pkix-crl",

  /**
   * **application/pem-certificate-chain**
   *
   * PEM-encoded certificate chain.
   *
   * @see [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555)
   */
  ApplicationPemCertificateChain = "application/pem-certificate-chain",

  // --- Patch Formats ---

  /**
   * **application/json-patch+json**
   *
   * JSON Patch document for applying changes to JSON documents.
   *
   * @see [RFC 6902](https://www.rfc-editor.org/rfc/rfc6902)
   */
  ApplicationJsonPatchJson = "application/json-patch+json",

  /**
   * **application/merge-patch+json**
   *
   * JSON Merge Patch document.
   *
   * @see [RFC 7396](https://www.rfc-editor.org/rfc/rfc7396)
   */
  ApplicationMergePatchJson = "application/merge-patch+json",

  // --- Feed Formats ---

  /**
   * **application/atom+xml**
   *
   * Atom Syndication Format feed.
   *
   * @see [RFC 4287](https://www.rfc-editor.org/rfc/rfc4287)
   */
  ApplicationAtomXml = "application/atom+xml",

  /**
   * **application/rss+xml**
   *
   * RSS feed format. Note: Not officially registered but widely used.
   */
  ApplicationRssXml = "application/rss+xml",

  /**
   * **application/activity+json**
   *
   * ActivityStreams 2.0 JSON format (used by ActivityPub).
   *
   * @see [W3C ActivityStreams](https://www.w3.org/TR/activitystreams-core/)
   */
  ApplicationActivityJson = "application/activity+json",

  // --- Geographic/Geospatial ---

  /**
   * **application/geo+json**
   *
   * GeoJSON format for encoding geographic data structures.
   *
   * @see [RFC 7946](https://www.rfc-editor.org/rfc/rfc7946)
   */
  ApplicationGeoJson = "application/geo+json",

  /**
   * **application/gml+xml**
   *
   * Geography Markup Language (GML) format.
   */
  ApplicationGmlXml = "application/gml+xml",

  // --- API Specification Formats ---

  /**
   * **application/schema+json**
   *
   * JSON Schema document. Note: Not in IANA registry but commonly used.
   */
  ApplicationSchemaJson = "application/schema+json",

  /**
   * **application/openapi+json**
   *
   * OpenAPI specification in JSON. Note: Not in IANA registry.
   */
  ApplicationOpenapiJson = "application/openapi+json",

  /**
   * **application/openapi+yaml**
   *
   * OpenAPI specification in YAML. Note: Not in IANA registry.
   */
  ApplicationOpenapiYaml = "application/openapi+yaml",

  /**
   * **application/asyncapi+json**
   *
   * AsyncAPI specification in JSON format.
   */
  ApplicationAsyncapiJson = "application/asyncapi+json",

  /**
   * **application/asyncapi+yaml**
   *
   * AsyncAPI specification in YAML format.
   */
  ApplicationAsyncapiYaml = "application/asyncapi+yaml",

  // --- Semantic Web / RDF ---

  /**
   * **application/rdf+xml**
   *
   * RDF/XML format for Resource Description Framework data.
   *
   * @see [RFC 3870](https://www.rfc-editor.org/rfc/rfc3870)
   */
  ApplicationRdfXml = "application/rdf+xml",

  /**
   * **application/n-quads**
   *
   * N-Quads RDF format.
   */
  ApplicationNQuads = "application/n-quads",

  /**
   * **application/n-triples**
   *
   * N-Triples RDF format.
   */
  ApplicationNTriples = "application/n-triples",

  // --- Calendar & Contact ---

  /**
   * **application/calendar+json**
   *
   * jCal (JSON format for iCalendar).
   *
   * @see [RFC 7265](https://www.rfc-editor.org/rfc/rfc7265)
   */
  ApplicationCalendarJson = "application/calendar+json",

  /**
   * **application/calendar+xml**
   *
   * xCal (XML format for iCalendar).
   *
   * @see [RFC 6321](https://www.rfc-editor.org/rfc/rfc6321)
   */
  ApplicationCalendarXml = "application/calendar+xml",

  // --- Office Formats ---

  /**
   * **application/msword**
   *
   * Microsoft Word document (.doc).
   */
  ApplicationMsword = "application/msword",

  /**
   * **application/vnd.openxmlformats-officedocument.wordprocessingml.document**
   *
   * Microsoft Word document (.docx) - Office Open XML format.
   */
  ApplicationDocx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document",

  /**
   * **application/vnd.openxmlformats-officedocument.spreadsheetml.sheet**
   *
   * Microsoft Excel spreadsheet (.xlsx) - Office Open XML format.
   */
  ApplicationXlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

  /**
   * **application/vnd.openxmlformats-officedocument.presentationml.presentation**
   *
   * Microsoft PowerPoint presentation (.pptx) - Office Open XML format.
   */
  ApplicationPptx = "application/vnd.openxmlformats-officedocument.presentationml.presentation",

  /**
   * **application/vnd.oasis.opendocument.text**
   *
   * OpenDocument Text document (.odt).
   */
  ApplicationOdt = "application/vnd.oasis.opendocument.text",

  /**
   * **application/vnd.oasis.opendocument.spreadsheet**
   *
   * OpenDocument Spreadsheet (.ods).
   */
  ApplicationOds = "application/vnd.oasis.opendocument.spreadsheet",

  /**
   * **application/vnd.oasis.opendocument.presentation**
   *
   * OpenDocument Presentation (.odp).
   */
  ApplicationOdp = "application/vnd.oasis.opendocument.presentation",

  // --- Container/Archive Formats ---

  /**
   * **application/epub+zip**
   *
   * EPUB electronic publication format.
   */
  ApplicationEpubZip = "application/epub+zip",

  /**
   * **application/java-archive**
   *
   * Java Archive (JAR) file.
   */
  ApplicationJavaArchive = "application/java-archive",

  // --- Streaming/Media Manifests ---

  /**
   * **application/dash+xml**
   *
   * MPEG-DASH Media Presentation Description (MPD).
   */
  ApplicationDashXml = "application/dash+xml",

  /**
   * **application/vnd.apple.mpegurl**
   *
   * HTTP Live Streaming (HLS) playlist. Note: Use for .m3u8 files.
   */
  ApplicationMpegurl = "application/vnd.apple.mpegurl",

  /**
   * **application/mp4**
   *
   * MP4 container format (when not primarily video/audio).
   *
   * @see [RFC 4337](https://www.rfc-editor.org/rfc/rfc4337)
   */
  ApplicationMp4 = "application/mp4",

  /**
   * **application/ogg**
   *
   * Ogg container format (when multiplexed or application data).
   *
   * @see [RFC 5334](https://www.rfc-editor.org/rfc/rfc5334)
   */
  ApplicationOgg = "application/ogg",

  // --- WebAssembly ---

  /**
   * **application/wasm**
   *
   * WebAssembly binary format. Note: Not in IANA registry but standardized by W3C.
   */
  ApplicationWasm = "application/wasm",

  // --- DNS ---

  /**
   * **application/dns**
   *
   * DNS data.
   *
   * @see [RFC 4027](https://www.rfc-editor.org/rfc/rfc4027)
   */
  ApplicationDns = "application/dns",

  /**
   * **application/dns+json**
   *
   * DNS JSON format.
   *
   * @see [RFC 8427](https://www.rfc-editor.org/rfc/rfc8427)
   */
  ApplicationDnsJson = "application/dns+json",

  /**
   * **application/dns-message**
   *
   * DNS message format (used in DoH).
   *
   * @see [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)
   */
  ApplicationDnsMessage = "application/dns-message",

  // --- YAML ---

  /**
   * **application/yaml**
   *
   * YAML Ain't Markup Language. Note: Use text/yaml for text-based YAML.
   */
  ApplicationYaml = "application/yaml",

  // --- TOML ---

  /**
   * **application/toml**
   *
   * Tom's Obvious, Minimal Language. Note: Not in IANA registry.
   */
  ApplicationToml = "application/toml",

  // --- Other Common Application Types ---

  /**
   * **application/postscript**
   *
   * PostScript document.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  ApplicationPostscript = "application/postscript",

  /**
   * **application/rtf**
   *
   * Rich Text Format document. Note: text/rtf is also valid.
   */
  ApplicationRtf = "application/rtf",

  /**
   * **application/sql**
   *
   * SQL script/query. Note: Not in IANA registry but commonly used.
   */
  ApplicationSql = "application/sql",

  /**
   * **application/graphql**
   *
   * GraphQL query/schema. Note: Not in IANA registry but commonly used.
   */
  ApplicationGraphql = "application/graphql",

  /**
   * **application/graphql+json**
   *
   * GraphQL response in JSON format. Note: Not in IANA registry.
   */
  ApplicationGraphqlJson = "application/graphql+json",

  /**
   * **application/manifest+json**
   *
   * Web App Manifest JSON format.
   */
  ApplicationManifestJson = "application/manifest+json",

  /**
   * **application/node**
   *
   * Node.js executable module.
   */
  ApplicationNode = "application/node",

  /**
   * **application/http**
   *
   * HTTP message format.
   *
   * @see [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
   */
  ApplicationHttp = "application/http",

  // ============================================================================
  // audio/* - Audio content
  // ============================================================================

  /**
   * **audio/mpeg**
   *
   * MPEG audio (includes MP3).
   *
   * @see [RFC 3003](https://www.rfc-editor.org/rfc/rfc3003)
   */
  AudioMpeg = "audio/mpeg",

  /**
   * **audio/mp4**
   *
   * MP4 audio container (AAC, etc.).
   *
   * @see [RFC 4337](https://www.rfc-editor.org/rfc/rfc4337)
   */
  AudioMp4 = "audio/mp4",

  /**
   * **audio/aac**
   *
   * Advanced Audio Coding (AAC) format.
   */
  AudioAac = "audio/aac",

  /**
   * **audio/ogg**
   *
   * Ogg audio container (Vorbis, Opus, etc.).
   *
   * @see [RFC 5334](https://www.rfc-editor.org/rfc/rfc5334)
   */
  AudioOgg = "audio/ogg",

  /**
   * **audio/opus**
   *
   * Opus audio codec.
   *
   * @see [RFC 7587](https://www.rfc-editor.org/rfc/rfc7587)
   */
  AudioOpus = "audio/opus",

  /**
   * **audio/vorbis**
   *
   * Vorbis audio codec.
   *
   * @see [RFC 5215](https://www.rfc-editor.org/rfc/rfc5215)
   */
  AudioVorbis = "audio/vorbis",

  /**
   * **audio/flac**
   *
   * Free Lossless Audio Codec (FLAC).
   *
   * @see [RFC 9639](https://www.rfc-editor.org/rfc/rfc9639)
   */
  AudioFlac = "audio/flac",

  /**
   * **audio/wav**
   *
   * Waveform Audio File Format. Note: audio/vnd.wave is the registered type.
   */
  AudioWav = "audio/wav",

  /**
   * **audio/webm**
   *
   * WebM audio container. Note: Not in IANA registry, use audio/webm.
   */
  AudioWebm = "audio/webm",

  /**
   * **audio/basic**
   *
   * Basic audio format (8-bit mu-law, 8kHz).
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  AudioBasic = "audio/basic",

  /**
   * **audio/midi**
   *
   * MIDI audio. Note: audio/midi is commonly used; audio/sp-midi is registered.
   */
  AudioMidi = "audio/midi",

  /**
   * **audio/3gpp**
   *
   * 3GPP audio.
   *
   * @see [RFC 3839](https://www.rfc-editor.org/rfc/rfc3839)
   */
  Audio3gpp = "audio/3gpp",

  /**
   * **audio/3gpp2**
   *
   * 3GPP2 audio.
   *
   * @see [RFC 4393](https://www.rfc-editor.org/rfc/rfc4393)
   */
  Audio3gpp2 = "audio/3gpp2",

  /**
   * **audio/matroska**
   *
   * Matroska audio container.
   *
   * @see [RFC 9559](https://www.rfc-editor.org/rfc/rfc9559)
   */
  AudioMatroska = "audio/matroska",

  // ============================================================================
  // font/* - Font formats
  // ============================================================================

  /**
   * **font/otf**
   *
   * OpenType font format.
   *
   * @see [RFC 8081](https://www.rfc-editor.org/rfc/rfc8081)
   */
  FontOtf = "font/otf",

  /**
   * **font/ttf**
   *
   * TrueType font format.
   *
   * @see [RFC 8081](https://www.rfc-editor.org/rfc/rfc8081)
   */
  FontTtf = "font/ttf",

  /**
   * **font/woff**
   *
   * Web Open Font Format (WOFF) 1.0.
   *
   * @see [RFC 8081](https://www.rfc-editor.org/rfc/rfc8081)
   */
  FontWoff = "font/woff",

  /**
   * **font/woff2**
   *
   * Web Open Font Format (WOFF) 2.0.
   *
   * @see [RFC 8081](https://www.rfc-editor.org/rfc/rfc8081)
   */
  FontWoff2 = "font/woff2",

  /**
   * **font/sfnt**
   *
   * SFNT (Spline Font) format - base format for TrueType/OpenType.
   *
   * @see [RFC 8081](https://www.rfc-editor.org/rfc/rfc8081)
   */
  FontSfnt = "font/sfnt",

  /**
   * **font/collection**
   *
   * Font collection (multiple fonts in one file).
   *
   * @see [RFC 8081](https://www.rfc-editor.org/rfc/rfc8081)
   */
  FontCollection = "font/collection",

  // ============================================================================
  // haptics/* - Haptic feedback data
  // ============================================================================

  /**
   * **haptics/ivs**
   *
   * IVS haptic effect format.
   *
   * @see [RFC 9695](https://www.rfc-editor.org/rfc/rfc9695)
   */
  HapticsIvs = "haptics/ivs",

  /**
   * **haptics/hjif**
   *
   * Haptics JSON Interchange Format.
   *
   * @see [RFC 9695](https://www.rfc-editor.org/rfc/rfc9695)
   */
  HapticsHjif = "haptics/hjif",

  /**
   * **haptics/hmpg**
   *
   * MPEG Haptics format.
   *
   * @see [RFC 9695](https://www.rfc-editor.org/rfc/rfc9695)
   */
  HapticsHmpg = "haptics/hmpg",

  // ============================================================================
  // image/* - Image content
  // ============================================================================

  /**
   * **image/png**
   *
   * Portable Network Graphics (PNG) image.
   *
   * @see [W3C PNG Specification](https://www.w3.org/TR/PNG/)
   */
  ImagePng = "image/png",

  /**
   * **image/jpeg**
   *
   * JPEG image format.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  ImageJpeg = "image/jpeg",

  /**
   * **image/gif**
   *
   * Graphics Interchange Format (GIF) image.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  ImageGif = "image/gif",

  /**
   * **image/webp**
   *
   * WebP image format.
   *
   * @see [RFC 9649](https://www.rfc-editor.org/rfc/rfc9649)
   */
  ImageWebp = "image/webp",

  /**
   * **image/svg+xml**
   *
   * Scalable Vector Graphics (SVG) image.
   *
   * @see [W3C SVG](https://www.w3.org/TR/SVG/)
   */
  ImageSvgXml = "image/svg+xml",

  /**
   * **image/avif**
   *
   * AV1 Image File Format (AVIF).
   */
  ImageAvif = "image/avif",

  /**
   * **image/apng**
   *
   * Animated Portable Network Graphics (APNG).
   */
  ImageApng = "image/apng",

  /**
   * **image/bmp**
   *
   * Windows Bitmap image.
   *
   * @see [RFC 7903](https://www.rfc-editor.org/rfc/rfc7903)
   */
  ImageBmp = "image/bmp",

  /**
   * **image/tiff**
   *
   * Tagged Image File Format (TIFF).
   *
   * @see [RFC 3302](https://www.rfc-editor.org/rfc/rfc3302)
   */
  ImageTiff = "image/tiff",

  /**
   * **image/heic**
   *
   * High Efficiency Image Container (HEIC) - single image.
   */
  ImageHeic = "image/heic",

  /**
   * **image/heic-sequence**
   *
   * High Efficiency Image Container (HEIC) - image sequence.
   */
  ImageHeicSequence = "image/heic-sequence",

  /**
   * **image/heif**
   *
   * High Efficiency Image File Format (HEIF) - single image.
   */
  ImageHeif = "image/heif",

  /**
   * **image/heif-sequence**
   *
   * High Efficiency Image File Format (HEIF) - image sequence.
   */
  ImageHeifSequence = "image/heif-sequence",

  /**
   * **image/jxl**
   *
   * JPEG XL image format.
   */
  ImageJxl = "image/jxl",

  /**
   * **image/jp2**
   *
   * JPEG 2000 image.
   *
   * @see [RFC 3745](https://www.rfc-editor.org/rfc/rfc3745)
   */
  ImageJp2 = "image/jp2",

  /**
   * **image/vnd.microsoft.icon**
   *
   * Microsoft ICO icon format.
   */
  ImageIcon = "image/vnd.microsoft.icon",

  /**
   * **image/vnd.adobe.photoshop**
   *
   * Adobe Photoshop document (PSD).
   */
  ImagePsd = "image/vnd.adobe.photoshop",

  /**
   * **image/ktx**
   *
   * Khronos Texture (KTX) format.
   */
  ImageKtx = "image/ktx",

  /**
   * **image/ktx2**
   *
   * Khronos Texture (KTX) format version 2.
   */
  ImageKtx2 = "image/ktx2",

  /**
   * **image/wmf**
   *
   * Windows Metafile.
   *
   * @see [RFC 7903](https://www.rfc-editor.org/rfc/rfc7903)
   */
  ImageWmf = "image/wmf",

  /**
   * **image/emf**
   *
   * Enhanced Windows Metafile.
   *
   * @see [RFC 7903](https://www.rfc-editor.org/rfc/rfc7903)
   */
  ImageEmf = "image/emf",

  // ============================================================================
  // message/* - Message encapsulation formats
  // ============================================================================

  /**
   * **message/rfc822**
   *
   * Internet email message format.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  MessageRfc822 = "message/rfc822",

  /**
   * **message/http**
   *
   * HTTP message format.
   *
   * @see [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
   */
  MessageHttp = "message/http",

  /**
   * **message/partial**
   *
   * Partial message (for splitting large messages).
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  MessagePartial = "message/partial",

  /**
   * **message/external-body**
   *
   * External reference to message body.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  MessageExternalBody = "message/external-body",

  /**
   * **message/delivery-status**
   *
   * Email delivery status notification.
   *
   * @see [RFC 1894](https://www.rfc-editor.org/rfc/rfc1894)
   */
  MessageDeliveryStatus = "message/delivery-status",

  /**
   * **message/disposition-notification**
   *
   * Message disposition notification (read receipt).
   *
   * @see [RFC 8098](https://www.rfc-editor.org/rfc/rfc8098)
   */
  MessageDispositionNotification = "message/disposition-notification",

  /**
   * **message/feedback-report**
   *
   * Abuse feedback report format.
   *
   * @see [RFC 5965](https://www.rfc-editor.org/rfc/rfc5965)
   */
  MessageFeedbackReport = "message/feedback-report",

  /**
   * **message/global**
   *
   * Internationalized email message.
   *
   * @see [RFC 6532](https://www.rfc-editor.org/rfc/rfc6532)
   */
  MessageGlobal = "message/global",

  /**
   * **message/sip**
   *
   * SIP message format.
   *
   * @see [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261)
   */
  MessageSip = "message/sip",

  /**
   * **message/bhttp**
   *
   * Binary HTTP message format.
   *
   * @see [RFC 9292](https://www.rfc-editor.org/rfc/rfc9292)
   */
  MessageBhttp = "message/bhttp",

  // ============================================================================
  // model/* - 3D model formats
  // ============================================================================

  /**
   * **model/gltf+json**
   *
   * glTF (GL Transmission Format) JSON format.
   */
  ModelGltfJson = "model/gltf+json",

  /**
   * **model/gltf-binary**
   *
   * glTF binary format (.glb).
   */
  ModelGltfBinary = "model/gltf-binary",

  /**
   * **model/stl**
   *
   * Stereolithography (STL) 3D model format.
   */
  ModelStl = "model/stl",

  /**
   * **model/obj**
   *
   * Wavefront OBJ 3D model format.
   */
  ModelObj = "model/obj",

  /**
   * **model/mtl**
   *
   * Wavefront MTL material library format.
   */
  ModelMtl = "model/mtl",

  /**
   * **model/3mf**
   *
   * 3D Manufacturing Format.
   */
  Model3mf = "model/3mf",

  /**
   * **model/step**
   *
   * STEP (Standard for the Exchange of Product Data) format.
   */
  ModelStep = "model/step",

  /**
   * **model/iges**
   *
   * Initial Graphics Exchange Specification (IGES) format.
   */
  ModelIges = "model/iges",

  /**
   * **model/vrml**
   *
   * Virtual Reality Modeling Language.
   *
   * @see [RFC 2077](https://www.rfc-editor.org/rfc/rfc2077)
   */
  ModelVrml = "model/vrml",

  /**
   * **model/x3d+xml**
   *
   * X3D (Extensible 3D) XML format.
   */
  ModelX3dXml = "model/x3d+xml",

  /**
   * **model/vnd.usdz+zip**
   *
   * Universal Scene Description (USD) compressed format.
   */
  ModelUsdzZip = "model/vnd.usdz+zip",

  /**
   * **model/vnd.collada+xml**
   *
   * COLLADA 3D model format.
   */
  ModelColladaXml = "model/vnd.collada+xml",

  /**
   * **model/u3d**
   *
   * Universal 3D format.
   */
  ModelU3d = "model/u3d",

  // ============================================================================
  // multipart/* - Composite content types
  // ============================================================================

  /**
   * **multipart/form-data**
   *
   * Form data with file uploads. Standard encoding for HTML file upload forms.
   *
   * @see [RFC 7578](https://www.rfc-editor.org/rfc/rfc7578)
   */
  MultipartFormData = "multipart/form-data",

  /**
   * **multipart/mixed**
   *
   * Mixed content types in a single message.
   *
   * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046)
   */
  MultipartMixed = "multipart/mixed",

  /**
   * **multipart/alternative**
   *
   * Same content in different formats (e.g., plain text and HTML email).
   *
   * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046)
   */
  MultipartAlternative = "multipart/alternative",

  /**
   * **multipart/related**
   *
   * Related content (e.g., HTML with embedded images).
   *
   * @see [RFC 2387](https://www.rfc-editor.org/rfc/rfc2387)
   */
  MultipartRelated = "multipart/related",

  /**
   * **multipart/digest**
   *
   * Collection of messages.
   *
   * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046)
   */
  MultipartDigest = "multipart/digest",

  /**
   * **multipart/parallel**
   *
   * Parts intended to be displayed simultaneously.
   *
   * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046)
   */
  MultipartParallel = "multipart/parallel",

  /**
   * **multipart/byteranges**
   *
   * Multiple byte ranges in HTTP response.
   *
   * @see [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110)
   */
  MultipartByteranges = "multipart/byteranges",

  /**
   * **multipart/encrypted**
   *
   * Encrypted content.
   *
   * @see [RFC 1847](https://www.rfc-editor.org/rfc/rfc1847)
   */
  MultipartEncrypted = "multipart/encrypted",

  /**
   * **multipart/signed**
   *
   * Digitally signed content.
   *
   * @see [RFC 1847](https://www.rfc-editor.org/rfc/rfc1847)
   */
  MultipartSigned = "multipart/signed",

  /**
   * **multipart/report**
   *
   * Report message (e.g., delivery status).
   *
   * @see [RFC 6522](https://www.rfc-editor.org/rfc/rfc6522)
   */
  MultipartReport = "multipart/report",

  /**
   * **multipart/x-mixed-replace**
   *
   * Server push content replacement (streaming).
   */
  MultipartXMixedReplace = "multipart/x-mixed-replace",

  // ============================================================================
  // text/* - Human-readable text content
  // ============================================================================

  /**
   * **text/plain**
   *
   * Plain text without formatting.
   *
   * @see [RFC 2046](https://www.rfc-editor.org/rfc/rfc2046)
   */
  TextPlain = "text/plain",

  /**
   * **text/html**
   *
   * HyperText Markup Language (HTML) document.
   */
  TextHtml = "text/html",

  /**
   * **text/css**
   *
   * Cascading Style Sheets (CSS).
   *
   * @see [RFC 2318](https://www.rfc-editor.org/rfc/rfc2318)
   */
  TextCss = "text/css",

  /**
   * **text/javascript**
   *
   * JavaScript/ECMAScript source code.
   *
   * @see [RFC 9239](https://www.rfc-editor.org/rfc/rfc9239)
   */
  TextJavascript = "text/javascript",

  /**
   * **text/xml**
   *
   * XML document (text-based).
   *
   * @see [RFC 7303](https://www.rfc-editor.org/rfc/rfc7303)
   */
  TextXml = "text/xml",

  /**
   * **text/csv**
   *
   * Comma-Separated Values.
   *
   * @see [RFC 4180](https://www.rfc-editor.org/rfc/rfc4180)
   */
  TextCsv = "text/csv",

  /**
   * **text/tab-separated-values**
   *
   * Tab-Separated Values (TSV).
   */
  TextTsv = "text/tab-separated-values",

  /**
   * **text/markdown**
   *
   * Markdown formatted text.
   *
   * @see [RFC 7763](https://www.rfc-editor.org/rfc/rfc7763)
   */
  TextMarkdown = "text/markdown",

  /**
   * **text/calendar**
   *
   * iCalendar format for calendar data.
   *
   * @see [RFC 5545](https://www.rfc-editor.org/rfc/rfc5545)
   */
  TextCalendar = "text/calendar",

  /**
   * **text/vcard**
   *
   * vCard contact information format.
   *
   * @see [RFC 6350](https://www.rfc-editor.org/rfc/rfc6350)
   */
  TextVcard = "text/vcard",

  /**
   * **text/rtf**
   *
   * Rich Text Format.
   */
  TextRtf = "text/rtf",

  /**
   * **text/richtext**
   *
   * MIME Richtext format.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  TextRichtext = "text/richtext",

  /**
   * **text/enriched**
   *
   * Enriched text format.
   *
   * @see [RFC 1896](https://www.rfc-editor.org/rfc/rfc1896)
   */
  TextEnriched = "text/enriched",

  /**
   * **text/uri-list**
   *
   * List of URIs.
   *
   * @see [RFC 2483](https://www.rfc-editor.org/rfc/rfc2483)
   */
  TextUriList = "text/uri-list",

  /**
   * **text/dns**
   *
   * DNS zone file format.
   *
   * @see [RFC 4027](https://www.rfc-editor.org/rfc/rfc4027)
   */
  TextDns = "text/dns",

  /**
   * **text/SGML**
   *
   * Standard Generalized Markup Language.
   *
   * @see [RFC 1874](https://www.rfc-editor.org/rfc/rfc1874)
   */
  TextSgml = "text/SGML",

  /**
   * **text/turtle**
   *
   * RDF Turtle format.
   */
  TextTurtle = "text/turtle",

  /**
   * **text/n3**
   *
   * RDF N3 (Notation3) format.
   */
  TextN3 = "text/n3",

  /**
   * **text/troff**
   *
   * troff/groff formatted text.
   *
   * @see [RFC 4263](https://www.rfc-editor.org/rfc/rfc4263)
   */
  TextTroff = "text/troff",

  /**
   * **text/vtt**
   *
   * WebVTT (Web Video Text Tracks) subtitles.
   */
  TextVtt = "text/vtt",

  /**
   * **text/cache-manifest**
   *
   * HTML5 Application Cache manifest.
   *
   * @deprecated Use Service Workers instead.
   */
  TextCacheManifest = "text/cache-manifest",

  /**
   * **text/event-stream**
   *
   * Server-Sent Events (SSE) stream. Note: Not in IANA registry but standardized.
   */
  TextEventStream = "text/event-stream",

  /**
   * **text/x-yaml**
   *
   * YAML format. Note: Not officially registered; use application/yaml for JSON-like data.
   */
  TextYaml = "text/x-yaml",

  // ============================================================================
  // video/* - Video content
  // ============================================================================

  /**
   * **video/mp4**
   *
   * MP4 video container.
   *
   * @see [RFC 4337](https://www.rfc-editor.org/rfc/rfc4337)
   */
  VideoMp4 = "video/mp4",

  /**
   * **video/mpeg**
   *
   * MPEG video.
   *
   * @see [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045)
   */
  VideoMpeg = "video/mpeg",

  /**
   * **video/ogg**
   *
   * Ogg video container (Theora, etc.).
   *
   * @see [RFC 5334](https://www.rfc-editor.org/rfc/rfc5334)
   */
  VideoOgg = "video/ogg",

  /**
   * **video/webm**
   *
   * WebM video container. Note: Not in IANA registry but widely supported.
   */
  VideoWebm = "video/webm",

  /**
   * **video/quicktime**
   *
   * QuickTime video format.
   *
   * @see [RFC 6381](https://www.rfc-editor.org/rfc/rfc6381)
   */
  VideoQuicktime = "video/quicktime",

  /**
   * **video/3gpp**
   *
   * 3GPP video.
   *
   * @see [RFC 3839](https://www.rfc-editor.org/rfc/rfc3839)
   */
  Video3gpp = "video/3gpp",

  /**
   * **video/3gpp2**
   *
   * 3GPP2 video.
   *
   * @see [RFC 4393](https://www.rfc-editor.org/rfc/rfc4393)
   */
  Video3gpp2 = "video/3gpp2",

  /**
   * **video/H264**
   *
   * H.264/AVC video codec.
   *
   * @see [RFC 6184](https://www.rfc-editor.org/rfc/rfc6184)
   */
  VideoH264 = "video/H264",

  /**
   * **video/H265**
   *
   * H.265/HEVC video codec.
   *
   * @see [RFC 7798](https://www.rfc-editor.org/rfc/rfc7798)
   */
  VideoH265 = "video/H265",

  /**
   * **video/H266**
   *
   * H.266/VVC video codec.
   *
   * @see [RFC 9328](https://www.rfc-editor.org/rfc/rfc9328)
   */
  VideoH266 = "video/H266",

  /**
   * **video/AV1**
   *
   * AV1 video codec.
   */
  VideoAv1 = "video/AV1",

  /**
   * **video/VP8**
   *
   * VP8 video codec. Note: Not in IANA registry.
   */
  VideoVp8 = "video/VP8",

  /**
   * **video/VP9**
   *
   * VP9 video codec. Note: Not in IANA registry.
   */
  VideoVp9 = "video/VP9",

  /**
   * **video/matroska**
   *
   * Matroska video container (MKV).
   *
   * @see [RFC 9559](https://www.rfc-editor.org/rfc/rfc9559)
   */
  VideoMatroska = "video/matroska",

  /**
   * **video/matroska-3d**
   *
   * Matroska 3D video container.
   *
   * @see [RFC 9559](https://www.rfc-editor.org/rfc/rfc9559)
   */
  VideoMatroska3d = "video/matroska-3d",

  /**
   * **video/raw**
   *
   * Raw uncompressed video.
   *
   * @see [RFC 4175](https://www.rfc-editor.org/rfc/rfc4175)
   */
  VideoRaw = "video/raw",

  /**
   * **video/JPEG**
   *
   * Motion JPEG video.
   *
   * @see [RFC 3555](https://www.rfc-editor.org/rfc/rfc3555)
   */
  VideoJpeg = "video/JPEG",

  /**
   * **video/jpeg2000**
   *
   * Motion JPEG 2000 video.
   *
   * @see [RFC 5371](https://www.rfc-editor.org/rfc/rfc5371)
   */
  VideoJpeg2000 = "video/jpeg2000",

  /**
   * **video/FFV1**
   *
   * FFV1 lossless video codec.
   *
   * @see [RFC 9043](https://www.rfc-editor.org/rfc/rfc9043)
   */
  VideoFfv1 = "video/FFV1",

  /**
   * **video/lottie+json**
   *
   * Lottie animation format (JSON-based).
   */
  VideoLottieJson = "video/lottie+json",

  /**
   * **video/vnd.mpegurl**
   *
   * M3U/M3U8 playlist format.
   */
  VideoMpegurl = "video/vnd.mpegurl",
}
