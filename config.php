<?php
/**
 * Configuration for IP Lookup Tool
 * - MMDB database paths and service definitions
 * - Enabled/disabled status for each service
 * - Application settings
 */

return [
    // ─── Application Settings ─────────────────────────────────────────────────
    'blocklist_csvs_dir' => __DIR__ . '/blocklist_csvs',
    
    // ─── GeoIP Database Configuration ──────────────────────────────────────────
    // Organized by service provider. Each service can be enabled/disabled independently.
    'databases' => [
        [
            'id'      => 'maxmind',
            'label'   => 'MaxMind GeoLite2',
            'enabled' => false,  // Enable/disable this service by default
            'databases' => [
                [
                    'file' => 'GeoLite2-Country.mmdb',  // MaxMind Country database
                    'type' => 'maxmind_country',
                ],
                [
                    'file' => 'GeoLite2-ASN.mmdb',      // MaxMind ASN database
                    'type' => 'maxmind_asn',
                ],
            ],
        ],
        [
            'id'      => 'iplocate',
            'label'   => 'iplocate.io',
            'enabled' => true,  // Enable/disable this service by default
            'databases' => [
                [
                    'file' => 'ip-to-country.mmdb',     // iplocate Country database
                    'type' => 'iplocate_country',
                ],
                [
                    'file' => 'ip-to-asn.mmdb',         // iplocate ASN database
                    'type' => 'iplocate_asn',
                ],
            ],
        ],
        [
            'id'      => 'ipinfo',
            'label'   => 'ipinfo Lite',
            'enabled' => true,  // Enable/disable this service by default
            'databases' => [
                [
                    'file' => 'ipinfo_lite.mmdb',       // ipinfo Lite database (combines country and ASN)
                    'type' => 'ipinfo',
                ],
            ],
        ],
    ],
];
