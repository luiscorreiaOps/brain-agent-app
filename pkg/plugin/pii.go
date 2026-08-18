package plugin

import "regexp"

// piiPatterns are deliberately simple, high-signal regexes -- this is a
// heuristic flag for a human reviewer (Brain Hub), not a compliance
// guarantee. Covers both American (SSN) and European (IBAN, EU VAT) national
// document/identifier formats alongside the generic ones (email, IP, card
// numbers), not just Brazilian CPF. False negatives are expected (PII in a
// shape these patterns don't cover slips through silently); false positives
// are an acceptable cost given the alternative is no signal at all. Never
// used to block a write -- only to surface a warning alongside the fact.
var piiPatterns = []*regexp.Regexp{
	// Email address.
	regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`),
	// Brazilian CPF, with or without punctuation (xxx.xxx.xxx-xx / 11 digits).
	regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`),
	// US Social Security Number (xxx-xx-xxxx), the closest US equivalent to
	// CPF as a national personal-identifier document format.
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	// IBAN (International Bank Account Number) -- the standard bank-account
	// document identifier across the EU/EEA and beyond: 2-letter country
	// code, 2 check digits, up to 30 alphanumeric characters.
	regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
	// EU VAT identification number (2-letter country code + up to 12
	// alphanumeric characters), e.g. DE123456789, FR12345678901.
	regexp.MustCompile(`\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)\d{8,12}\b`),
	// Mexican CURP (Clave Única de Registro de Población) -- an 18-character
	// national ID with a fixed, distinctive structure: 4 letters, 6 digits
	// (birthdate YYMMDD), a sex letter (H/M), 2 letters (state), 3
	// consonants, then 1 alphanumeric + 1 check digit.
	regexp.MustCompile(`\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b`),
	// Chilean RUT/RUN (national ID / tax ID) -- 1-2 digits, 3, 3, a hyphen,
	// then a check digit or 'K', e.g. 12.345.678-9.
	regexp.MustCompile(`\b\d{1,2}\.\d{3}\.\d{3}-[\dkK]\b`),
	// A dotted 7-8 digit national ID number, the common shape for Spanish-
	// speaking Latin American countries' DNI/cédula (e.g. Argentina's DNI,
	// 12.345.678) when written with thousands separators.
	regexp.MustCompile(`\b\d{1,2}\.\d{3}\.\d{3}\b`),
	// IPv4 address.
	regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`),
	// A long run of digits (13-19), grouped or not -- credit-card-shaped
	// (Visa/Mastercard/Amex are all issued globally, US and EU alike).
	regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`),
	// A bearer/API-key-shaped token: a long run of base64url-ish characters,
	// the same general shape as the tokens this plugin already refuses to
	// reveal in conversation (see the skill pack's secret-handling rule) --
	// worth flagging if one ends up persisted into a memory fact too.
	regexp.MustCompile(`\b[A-Za-z0-9_\-]{32,}\b`),
}

// detectPII reports whether fact looks like it contains personal or
// sensitive data, per piiPatterns above. This is a heuristic used to flag a
// fact for human review in Brain Hub -- it never blocks a write, and a
// false negative (real PII missed) is expected, not a bug to eliminate.
func detectPII(fact string) bool {
	for _, re := range piiPatterns {
		if re.MatchString(fact) {
			return true
		}
	}
	return false
}
