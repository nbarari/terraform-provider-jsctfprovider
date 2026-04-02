// Copyright 2025, Jamf Software LLC.
package securepolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"jsctfprovider/internal/auth"
)

// securePolicyThreat represents a single threat category entry in the secure policy payload.
// Only the fields required for read/write are declared here; the rest are captured in raw JSON
// and passed through unchanged so the full payload round-trips cleanly.
type securePolicyThreat struct {
	ThreatCategoryID string          `json:"threatCategoryId"`
	Action           threatAction    `json:"action"`
	RawRest          json.RawMessage `json:"-"` // not serialised — see marshalThreats
}

type threatAction struct {
	Response           string                 `json:"response"`
	NotificationPolicy map[string]interface{} `json:"notificationPolicy"`
	ReportingPolicy    threatReportingPolicy  `json:"reportingPolicy"`
	AnalysisPolicy     map[string]interface{} `json:"analysisPolicy"`
}

type threatReportingPolicy struct {
	Types             []interface{} `json:"types"`
	DeviceDelay       string        `json:"deviceDelay"`
	AffectsDeviceRisk bool          `json:"affectsDeviceRisk"`
	Severity          string        `json:"severity"`
}

// securePolicyPayload mirrors the top-level structure returned by GET and accepted by PUT.
// threatCategories is kept as raw JSON so that all threat entries are round-tripped
// without losing unknown fields.
type securePolicyPayload struct {
	SummaryNotificationPolicy map[string]interface{} `json:"summaryNotificationPolicy"`
	CustomerConfiguration     map[string]interface{} `json:"customerConfiguration"`
	ThreatCategories          json.RawMessage        `json:"threatCategories"`
	GroupPolicyOverrides      interface{}            `json:"groupPolicyOverrides"`
}

const securePolicyBaseURL = "https://radar.wandera.com/gate/secure-policy-service/v1/secure-policies/customers/{customerid}"

// validSeverities is the set of accepted severity strings.
var validSeverities = []string{"HIGHEST", "HIGH", "MEDIUM", "LOW", "LOWEST", "INFO"}

// threatCategoryDef describes a single managed threat category: its API identifier,
// the corresponding Terraform attribute name, a human-readable description, and the
// tenant default severity used when the resource is destroyed.
type threatCategoryDef struct {
	APIId           string
	TFAttribute     string
	Description     string
	DefaultSeverity string
}

// threatCategories is the authoritative list of threat categories exposed as Terraform
// attributes.  Add additional entries here as more overrides are introduced.
var threatCategories = []threatCategoryDef{
	{"ACCESS_PHISHING_HOST", "access_phishing_host_severity", "Phishing", "HIGHEST"},
	{"APP_LEAK_CREDIT_CARD", "app_leak_credit_card_severity", "App Data Leak: Credit Card", "HIGH"},
	{"APP_LEAK_PASSWORD", "app_leak_password_severity", "App Data Leak: Password", "MEDIUM"},
	{"APP_LEAK_EMAIL", "app_leak_email_severity", "App Data Leak: Email", "LOW"},
	{"APP_LEAK_USERID", "app_leak_userid_severity", "App Data Leak: User Identity", "LOW"},
	{"APP_LEAK_LOCATION", "app_leak_location_severity", "App Data Leak: Location", "LOW"},
	{"RESOURCE_LEAK_CREDIT_CARD", "resource_leak_credit_card_severity", "Web Data Leak: Credit Card", "HIGH"},
	{"RESOURCE_LEAK_PASSWORD", "resource_leak_password_severity", "Web Data Leak: Password", "MEDIUM"},
	{"RESOURCE_LEAK_EMAIL", "resource_leak_email_severity", "Web Data Leak: Email", "LOW"},
	{"RESOURCE_LEAK_USERID", "resource_leak_userid_severity", "Web Data Leak: User Identity", "LOW"},
	{"RESOURCE_LEAK_LOCATION", "resource_leak_location_severity", "Web Data Leak: Location", "LOW"},
	{"ACCESS_BAD_HOST", "access_bad_host_severity", "Malware Network Traffic", "HIGH"},
	{"ACCESS_CRYPTOJACKING_HOST", "access_cryptojacking_host_severity", "Cryptojacking", "MEDIUM"},
	{"ACCESS_SPAM_HOST", "access_spam_host_severity", "Spam", "MEDIUM"},
	{"RISKY_APP_DOWNLOAD", "risky_app_download_severity", "Third Party App Store Traffic", "LOW"},
	{"APP_MALICIOUS_APP_IN_INVENTORY", "app_malicious_app_in_inventory_severity", "Generic Malware", "HIGHEST"},
	{"APP_SPYWARE_APP_IN_INVENTORY", "app_spyware_app_in_inventory_severity", "Spyware", "HIGHEST"},
	{"APP_TROJAN_MALWARE_APP_IN_INVENTORY", "app_trojan_malware_app_in_inventory_severity", "Trojan", "HIGHEST"},
	{"APP_RANSOMWARE_APP_IN_INVENTORY", "app_ransomware_app_in_inventory_severity", "Ransomware", "HIGHEST"},
	{"APP_BANKER_MALWARE_APP_IN_INVENTORY", "app_banker_malware_app_in_inventory_severity", "Banker", "HIGHEST"},
	{"APP_SMS_MALWARE_APP_IN_INVENTORY", "app_sms_malware_app_in_inventory_severity", "SMS Malware", "HIGHEST"},
	{"APP_ADWARE_APP_IN_INVENTORY", "app_adware_app_in_inventory_severity", "Adware", "HIGHEST"},
	{"APP_ROOTING_MALWARE_APP_IN_INVENTORY", "app_rooting_malware_app_in_inventory_severity", "Rooting Malware", "HIGHEST"},
	{"APP_POTENTIALLY_UNWANTED_APP_IN_INVENTORY", "app_potentially_unwanted_app_in_inventory_severity", "Potentially Unwanted Application", "MEDIUM"},
	{"APP_ADMIN_APP_IN_INVENTORY", "app_admin_app_in_inventory_severity", "Device Admin App Installed", "MEDIUM"},
	{"APP_SIDE_LOADED_APP_IN_INVENTORY", "app_side_loaded_app_in_inventory_severity", "Sideloaded App Installed", "MEDIUM"},
	{"APP_THIRD_PARTY_APP_STORES_IN_INVENTORY", "app_third_party_app_stores_in_inventory_severity", "Third Party App Stores Installed", "LOW"},
	{"APP_VULNERABLE_APP_IN_INVENTORY", "app_vulnerable_app_in_inventory_severity", "Vulnerable App Installed", "LOW"},
	{"CERTIFICATE_SSL_TRUST_COMPROMISE", "certificate_ssl_trust_compromise_severity", "Dangerous Certificate", "HIGHEST"},
	{"NETWORK_ACCESS_POINT_SSL_MITM_TRUSTED_VALID_CERT", "network_access_point_ssl_mitm_trusted_valid_cert_severity", "Man-in-the-Middle (Compromised Trust Store)", "HIGHEST"},
	{"NETWORK_ACCESS_POINT_SSL_MITM_UNTRUSTED_VALID_CERT", "network_access_point_ssl_mitm_untrusted_valid_cert_severity", "Man-in-the-Middle (Targeted Certificate Spoof)", "HIGH"},
	{"NETWORK_ACCESS_POINT_SSL_STRIP_MITM", "network_access_point_ssl_strip_mitm_severity", "Man-in-the-Middle (SSL Strip)", "HIGHEST"},
	{"RISKY_HOTSPOT", "risky_hotspot_severity", "Risky Hotspots", "MEDIUM"},
	{"OS_JAILBREAK", "os_jailbreak_severity", "Jailbreak", "HIGHEST"},
	{"OS_OUTDATED_OS", "os_outdated_os_severity", "Vulnerable OS (Major)", "HIGH"},
	{"OS_OUTDATED_OS_LOW", "os_outdated_os_low_severity", "Vulnerable OS (Minor)", "MEDIUM"},
	{"OS_OUT_OF_DATE_OS", "os_out_of_date_os_severity", "Out-of-Date OS", "LOW"},
	{"DEVICE_APP_INACTIVITY", "device_app_inactivity_severity", "App Inactivity", "MEDIUM"},
	{"DEVICE_STORAGE_ENCRYPTION_DISABLED", "device_storage_encryption_disabled_severity", "Device Encryption Disabled", "MEDIUM"},
	{"DEVICE_LOCK_SCREEN_DISABLED", "device_lock_screen_disabled_severity", "Lock Screen Disabled", "MEDIUM"},
	{"IOS_PROFILE", "ios_profile_severity", "Risky iOS Profile", "MEDIUM"},
	{"DEVICE_MISSING_ANDROID_SECURITY_PATCHES", "device_missing_android_security_patches_severity", "Android Security Patches Missing", "LOW"},
	{"DEVICE_UNKNOWN_SOURCES_ENABLED", "device_unknown_sources_enabled_severity", "Unknown Sources Enabled", "LOW"},
	{"DEVICE_USB_APP_VERIFICATION_DISABLED", "device_usb_app_verification_disabled_severity", "USB App Verification Disabled", "LOW"},
	{"DEVICE_USER_PASSWORD_DISABLED", "device_user_password_disabled_severity", "User Password Disabled", "LOW"},
	{"DEVICE_DEVELOPER_MODE_ENABLED", "device_developer_mode_enabled_severity", "Developer Mode Enabled", "LOWEST"},
	{"DEVICE_USB_DEBUGGING_ENABLED", "device_usb_debugging_enabled_severity", "USB Debugging Enabled", "LOWEST"},
	{"DEVICE_ANTIVIRUS_DISABLED", "device_antivirus_disabled_severity", "Antivirus Disabled", "MEDIUM"},
	{"DEVICE_FIREWALL_DISABLED", "device_firewall_disabled_severity", "Firewall Disabled", "MEDIUM"},
}

// ResourceSecurePolicy returns the schema.Resource for jsc_secure_policy.
func ResourceSecurePolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceSecurePolicyCreate,
		Read:   resourceSecurePolicyRead,
		Update: resourceSecurePolicyUpdate,
		Delete: resourceSecurePolicyDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"access_phishing_host_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the ACCESS_PHISHING_HOST threat category (Phishing). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_leak_credit_card_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGH",
				Description:  "Severity override for the APP_LEAK_CREDIT_CARD threat category (App Data Leak: Credit Card). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGH (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_leak_password_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the APP_LEAK_PASSWORD threat category (App Data Leak: Password). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_leak_email_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the APP_LEAK_EMAIL threat category (App Data Leak: Email). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_leak_userid_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the APP_LEAK_USERID threat category (App Data Leak: User Identity). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_leak_location_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the APP_LEAK_LOCATION threat category (App Data Leak: Location). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"resource_leak_credit_card_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGH",
				Description:  "Severity override for the RESOURCE_LEAK_CREDIT_CARD threat category (Web Data Leak: Credit Card). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGH (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"resource_leak_password_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the RESOURCE_LEAK_PASSWORD threat category (Web Data Leak: Password). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"resource_leak_email_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the RESOURCE_LEAK_EMAIL threat category (Web Data Leak: Email). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"resource_leak_userid_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the RESOURCE_LEAK_USERID threat category (Web Data Leak: User Identity). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"resource_leak_location_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the RESOURCE_LEAK_LOCATION threat category (Web Data Leak: Location). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"access_bad_host_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGH",
				Description:  "Severity override for the ACCESS_BAD_HOST threat category (Malware Network Traffic). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGH (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"access_cryptojacking_host_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the ACCESS_CRYPTOJACKING_HOST threat category (Cryptojacking). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"access_spam_host_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the ACCESS_SPAM_HOST threat category (Spam). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"risky_app_download_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the RISKY_APP_DOWNLOAD threat category (Third Party App Store Traffic). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_malicious_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_MALICIOUS_APP_IN_INVENTORY threat category (Generic Malware). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_spyware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_SPYWARE_APP_IN_INVENTORY threat category (Spyware). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_trojan_malware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_TROJAN_MALWARE_APP_IN_INVENTORY threat category (Trojan). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_ransomware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_RANSOMWARE_APP_IN_INVENTORY threat category (Ransomware). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_banker_malware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_BANKER_MALWARE_APP_IN_INVENTORY threat category (Banker). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_sms_malware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_SMS_MALWARE_APP_IN_INVENTORY threat category (SMS Malware). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_adware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_ADWARE_APP_IN_INVENTORY threat category (Adware). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_rooting_malware_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the APP_ROOTING_MALWARE_APP_IN_INVENTORY threat category (Rooting Malware). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_potentially_unwanted_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the APP_POTENTIALLY_UNWANTED_APP_IN_INVENTORY threat category (Potentially Unwanted Application). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_admin_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the APP_ADMIN_APP_IN_INVENTORY threat category (Device Admin App Installed). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_side_loaded_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the APP_SIDE_LOADED_APP_IN_INVENTORY threat category (Sideloaded App Installed). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_third_party_app_stores_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the APP_THIRD_PARTY_APP_STORES_IN_INVENTORY threat category (Third Party App Stores Installed). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"app_vulnerable_app_in_inventory_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the APP_VULNERABLE_APP_IN_INVENTORY threat category (Vulnerable App Installed). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"certificate_ssl_trust_compromise_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the CERTIFICATE_SSL_TRUST_COMPROMISE threat category (Dangerous Certificate). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"network_access_point_ssl_mitm_trusted_valid_cert_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the NETWORK_ACCESS_POINT_SSL_MITM_TRUSTED_VALID_CERT threat category (Man-in-the-Middle (Compromised Trust Store)). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"network_access_point_ssl_mitm_untrusted_valid_cert_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGH",
				Description:  "Severity override for the NETWORK_ACCESS_POINT_SSL_MITM_UNTRUSTED_VALID_CERT threat category (Man-in-the-Middle (Targeted Certificate Spoof)). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGH (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"network_access_point_ssl_strip_mitm_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the NETWORK_ACCESS_POINT_SSL_STRIP_MITM threat category (Man-in-the-Middle (SSL Strip)). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"risky_hotspot_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the RISKY_HOTSPOT threat category (Risky Hotspots). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"os_jailbreak_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGHEST",
				Description:  "Severity override for the OS_JAILBREAK threat category (Jailbreak). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGHEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"os_outdated_os_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HIGH",
				Description:  "Severity override for the OS_OUTDATED_OS threat category (Vulnerable OS (Major)). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to HIGH (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"os_outdated_os_low_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the OS_OUTDATED_OS_LOW threat category (Vulnerable OS (Minor)). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"os_out_of_date_os_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the OS_OUT_OF_DATE_OS threat category (Out-of-Date OS). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_app_inactivity_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the DEVICE_APP_INACTIVITY threat category (App Inactivity). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_storage_encryption_disabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the DEVICE_STORAGE_ENCRYPTION_DISABLED threat category (Device Encryption Disabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_lock_screen_disabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the DEVICE_LOCK_SCREEN_DISABLED threat category (Lock Screen Disabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"ios_profile_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the IOS_PROFILE threat category (Risky iOS Profile). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_missing_android_security_patches_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the DEVICE_MISSING_ANDROID_SECURITY_PATCHES threat category (Android Security Patches Missing). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_unknown_sources_enabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the DEVICE_UNKNOWN_SOURCES_ENABLED threat category (Unknown Sources Enabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_usb_app_verification_disabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the DEVICE_USB_APP_VERIFICATION_DISABLED threat category (USB App Verification Disabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_user_password_disabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOW",
				Description:  "Severity override for the DEVICE_USER_PASSWORD_DISABLED threat category (User Password Disabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOW (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_developer_mode_enabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOWEST",
				Description:  "Severity override for the DEVICE_DEVELOPER_MODE_ENABLED threat category (Developer Mode Enabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOWEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_usb_debugging_enabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "LOWEST",
				Description:  "Severity override for the DEVICE_USB_DEBUGGING_ENABLED threat category (USB Debugging Enabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to LOWEST (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_antivirus_disabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the DEVICE_ANTIVIRUS_DISABLED threat category (Antivirus Disabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
			"device_firewall_disabled_severity": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "MEDIUM",
				Description:  "Severity override for the DEVICE_FIREWALL_DISABLED threat category (Firewall Disabled). Valid values: HIGHEST, HIGH, MEDIUM, LOW, LOWEST, INFO. Defaults to MEDIUM (tenant default).",
				ValidateFunc: validation.StringInSlice(validSeverities, false),
			},
		},
	}
}

// getPolicy fetches the current secure policy from the API and returns the raw body bytes.
func getPolicy() ([]byte, error) {
	req, err := http.NewRequest("GET", securePolicyBaseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build jsc_secure_policy GET request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return nil, fmt.Errorf("jsc_secure_policy GET request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jsc_secure_policy GET returned unexpected status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read jsc_secure_policy GET response body: %v", err)
	}

	return body, nil
}

// applyOverrides mutates the ThreatCategories raw JSON in place, applying any severity
// overrides specified in the Terraform config.  All other fields in every threat entry
// are preserved exactly as received from the API.
func applyOverrides(raw json.RawMessage, overrides map[string]string) (json.RawMessage, error) {
	// Unmarshal into a slice of generic maps so every field is preserved.
	var threats []map[string]interface{}
	if err := json.Unmarshal(raw, &threats); err != nil {
		return nil, fmt.Errorf("failed to parse threatCategories: %v", err)
	}

	for i, threat := range threats {
		id, _ := threat["threatCategoryId"].(string)
		newSeverity, ok := overrides[id]
		if !ok {
			continue
		}

		// Navigate action → reportingPolicy → severity, creating intermediate maps
		// if they are unexpectedly missing so we never panic.
		action, ok := threat["action"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action' structure", id)
		}

		reportingPolicy, ok := action["reportingPolicy"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action.reportingPolicy' structure", id)
		}

		reportingPolicy["severity"] = newSeverity
		action["reportingPolicy"] = reportingPolicy
		threat["action"] = action
		threats[i] = threat
	}

	updated, err := json.Marshal(threats)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal threatCategories after applying overrides: %v", err)
	}

	return updated, nil
}

// putPolicy applies the provided severity overrides to the current policy and PUTs it back.
func putPolicy(overrides map[string]string) error {
	body, err := getPolicy()
	if err != nil {
		return err
	}

	var payload securePolicyPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("failed to parse jsc_secure_policy response: %v", err)
	}

	updatedThreats, err := applyOverrides(payload.ThreatCategories, overrides)
	if err != nil {
		return err
	}
	payload.ThreatCategories = updatedThreats

	putBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal jsc_secure_policy PUT payload: %v", err)
	}

	req, err := http.NewRequest("PUT", securePolicyBaseURL, bytes.NewBuffer(putBody))
	if err != nil {
		return fmt.Errorf("failed to build jsc_secure_policy PUT request: %v", err)
	}

	resp, err := auth.MakeRequest(req)
	if err != nil {
		return fmt.Errorf("jsc_secure_policy PUT request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("jsc_secure_policy PUT returned unexpected status: %s — %s", resp.Status, string(respBody))
	}

	return nil
}

// buildOverrides converts Terraform resource data into the overrides map expected by putPolicy.
func buildOverrides(d *schema.ResourceData) map[string]string {
	overrides := make(map[string]string, len(threatCategories))
	for _, tc := range threatCategories {
		overrides[tc.APIId] = d.Get(tc.TFAttribute).(string)
	}
	return overrides
}

func resourceSecurePolicyCreate(d *schema.ResourceData, m interface{}) error {
	if err := putPolicy(buildOverrides(d)); err != nil {
		return err
	}

	// Singleton: use a fixed string as the resource ID since there is exactly
	// one secure policy per JSC customer and no per-resource ID is returned.
	d.SetId("secure_policy")
	return nil
}

func resourceSecurePolicyRead(d *schema.ResourceData, m interface{}) error {
	body, err := getPolicy()
	if err != nil {
		return err
	}

	var payload securePolicyPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("failed to parse jsc_secure_policy read response: %v", err)
	}

	var threats []map[string]interface{}
	if err := json.Unmarshal(payload.ThreatCategories, &threats); err != nil {
		return fmt.Errorf("failed to parse threatCategories on read: %v", err)
	}

	// Build a lookup from API ID → TF attribute name for O(1) access per threat entry.
	lookupAttr := make(map[string]string, len(threatCategories))
	for _, tc := range threatCategories {
		lookupAttr[tc.APIId] = tc.TFAttribute
	}

	for _, threat := range threats {
		id, _ := threat["threatCategoryId"].(string)
		attr, ok := lookupAttr[id]
		if !ok {
			continue
		}

		severity, err := extractSeverity(threat, id)
		if err != nil {
			return err
		}
		if err := d.Set(attr, severity); err != nil {
			return fmt.Errorf("failed to set %s in state: %v", attr, err)
		}
	}

	return nil
}

func resourceSecurePolicyUpdate(d *schema.ResourceData, m interface{}) error {
	if err := putPolicy(buildOverrides(d)); err != nil {
		return err
	}
	return resourceSecurePolicyRead(d, m)
}

func resourceSecurePolicyDelete(d *schema.ResourceData, m interface{}) error {
	// "Delete" restores all managed overrides to their tenant defaults as defined
	// in the threatCategories table.
	defaults := make(map[string]string, len(threatCategories))
	for _, tc := range threatCategories {
		defaults[tc.APIId] = tc.DefaultSeverity
	}

	if err := putPolicy(defaults); err != nil {
		return err
	}

	d.SetId("")
	return nil
}

// extractSeverity is a helper that safely navigates action → reportingPolicy → severity
// for the given threat entry, returning a clear error if the structure is unexpected.
func extractSeverity(threat map[string]interface{}, id string) (string, error) {
	action, ok := threat["action"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action' structure on read", id)
	}

	reportingPolicy, ok := action["reportingPolicy"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action.reportingPolicy' structure on read", id)
	}

	severity, ok := reportingPolicy["severity"].(string)
	if !ok {
		return "", fmt.Errorf("jsc_secure_policy: threat %q has unexpected 'action.reportingPolicy.severity' type on read", id)
	}

	return severity, nil
}
