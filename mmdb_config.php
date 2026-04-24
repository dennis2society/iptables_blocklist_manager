<?php
/**
 * GeoIP Database Configuration
 * Organized by service provider. Each service can be enabled/disabled independently.
 */

return [
    [
        'id'    => 'maxmind',
        'label' => 'MaxMind GeoLite2',
        'databases' => [
            [
                'file' => 'GeoLite2-Country.mmdb',  // Specify the path/filename to the MaxMind Country database
                'type' => 'maxmind_country',
            ],
            [
                'file' => 'GeoLite2-ASN.mmdb',  // Specify the path/filename to the MaxMind ASN database
                'type' => 'maxmind_asn',
            ],
        ],
    ],
    [
        'id'    => 'iplocate',
        'label' => 'iplocate.io',
        'databases' => [
            [
                'file' => 'ip-to-country.mmdb',  // Specify the path/filename to the iplocate Country database
                'type' => 'iplocate_country',
            ],
            [
                'file' => 'ip-to-asn.mmdb',  // Specify the path/filename to the iplocate ASN database
                'type' => 'iplocate_asn',
            ],
        ],
    ],
    // ipinfo uses a combined database for both country and ASN information, so we only need one entry here
    [
        'id'    => 'ipinfo',
        'label' => 'ipinfo Lite',
        'databases' => [
            [
                'file' => 'ipinfo_lite.mmdb',  // Specify the path/filename to the ipinfo Lite database
                'type' => 'ipinfo',
            ],
        ],
    ],
];
