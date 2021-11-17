<?php

// RDAP.org main request handler
// Copyright 2018 Gavin Brown <gavin.brown@uk.com>

//
// CRC is a foundation library available from CentralNic:
//
require(dirname(__DIR__).'/CRC/CRC.php');

//
// initialise objects we'll use later
//
$HTTP	= new CRC_HTTP;
$UA	= new CRC_HTTPClient;
$BUCKET	= new CRC_MemCacheTokenBucket($_SERVER['SERVER_NAME']);

//
// check bearer token which allows rate limiting bypass
//
$TOKENS = explode("\n", trim(file_get_contents(dirname(__DIR__).'/tokens.txt')));
$HEADERS = apache_request_headers();
if (isset($HEADERS['authorization']) && 1 == preg_match('/^Bearer (.+)$/', $HEADERS['authorization'], $matches) && in_array($matches[1], $TOKENS)) {
	$limited = false;

} else {
	$limited = $BUCKET->check($_SERVER['HTTP_CF_CONNECTING_IP'], 3000, 300);

}

//
// Allow cross-origin requests:
//
$HTTP->header('Access-Control-Allow-Origin', '*');

//
// we don't have PATH_INFO so remove any query string from REQUEST_URI:
//
$path = preg_replace('/\?.*$/', '', $_SERVER['REQUEST_URI']);

//
// redirect / to about page
//
if ('/' == $path) {
	$HTTP->status(301, 'Moved Permanently');
	$HTTP->redirect('https://about.rdap.org/');

} else {
	// validate path
	$parts = preg_split('/\//', $path, 2, PREG_SPLIT_NO_EMPTY);
	if (2 != count($parts)) {
		rdap_error(400, 'Bad Request: queries must take the form /<type>/<handle>');

	} else {
		//
		// extract object type and object handle from the path
		//
		list($type, $object) = $parts;

		if (!in_array($type, array('domain', 'ip', 'autnum', 'entity'))) {
            //
            // invalid object type
            //
			rdap_error(400, sprintf("Bad Request: unsupported object type '%s'", $type));

		} elseif ($limited) {
            //
            // rate limit exceeded
            //
			$HTTP->header('Retry-After', 300);
			rdap_error(429, 'Rate Limit Exceeded');

		} else {
			//
			// determine which bootstrap registry to use
			//
			if ('domain' == $type) {
				$labels = explode('.', lc($object));
				$parent = implode('.', array_slice($labels, 1));
				$url = 'https://data.iana.org/rdap/dns.json';

			} elseif ('ip' == $type) {
				//
				// turn $object into a CRC_IP object
				//
				try {
					$object = CRC_IP::fromString($object, (strpos($object, '/') ? CRC_IP::CONVERT_TONETWORK : CRC_IP::CONVERT_TOADDRESS));

				} catch (Exception $e) {
					rdap_error(400, 'Bad Request: invalid format for IP query');

				}

				$url = (AF_INET == $object->family() ? 'https://data.iana.org/rdap/ipv4.json' : 'https://data.iana.org/rdap/ipv6.json');

			} elseif ('autnum' == $type) {
				$object = intval($object);

				$url = 'https://data.iana.org/rdap/asn.json';

			} elseif ('entity' == $type) {
				$parts = explode('-', $object);
				$tag = array_pop($parts);

				$url = 'https://data.iana.org/rdap/object-tags.json';
			}

			//
			// refresh registry from IANA - the mirror() function won't send a request to IANA if the local file is still fresh
			//
			$json = $UA->mirror($url, 86400);
			if (PEAR::isError($json)) {
				rdap_error(504, 'Unable to retrieve bootstrap file from IANA');

			} else {
				$registry = json_decode($json);

				//
				// scan through each service in the registry, putting any which match into
				// $matches, along with a corresponding "weight", so they can be sorted
				// by weight to find the closest-matching service:
				//
				$matches = array();
				foreach ($registry->services as $service) {
					if ('entity' == $type) {
						// first item in the array is the registrant for some reason
						list(,$values, $urls) = $service;

					} else {
						list($values, $urls) = $service;

					}

					foreach ($values as $value) {
						if ('autnum' == $type) {
							if (intval($value) == $object) {
								//
								// exact match, weight is zero
								//
								$matches[] = array(0, $urls);
								break 2;

							} elseif (1 == preg_match('/^(\d+)-(\d+)$/', $value, $numbers)) {
								$min = intval($numbers[1]);
								$max = intval($numbers[2]);

								if ($object >= $min && $object <= $max) {
									//
									// enclosing match, weight is the width of the range
									//
									$matches[] = array(($max - $min), $urls);
								}

							}

						} elseif ('ip' == $type) {
							try {
								$net = CRC_IP::fromString($value, CRC_IP::CONVERT_TONETWORK);

								if ($net->equals($object)) {
									//
									// exact match, weight is zero
									//
									$matches[] = array(0, $urls);
									break 2;

								} elseif ($net->contains($object)) {
									//
									// enclosing match, weight is the length of the suffix
									//
									$matches[] = array($net->bits() - $net->getPrefix(), $urls);

								}

							} catch (Exception $e) {
								continue;

							}

						} elseif ('domain' == $type) {
							if (lc($value) == $parent) {
								$matches[] = array(0, $urls);
								break 2;
							}

						} elseif ('entity' == $type) {
							if (lc($value) == lc($tag)) {
								$matches[] = array(0, $urls);
								break 2;

							}

						}
					}
				}

				if (count($matches) < 1) {
					rdap_error(404, sprintf('%s %s not found in IANA boostrap file', $type, $object));

				} else {
					//
					// sort matching services by weight, lowest first
					//
					usort($matches, 'weighted_sort');
					$match = array_shift($matches);
					$urls = $match[1];

					//
					// prefer HTTPS URLs to other URLs
					//
					$https_urls = preg_grep('/^https:/', $urls);
					if (count($https_urls) > 0) {
						$base = array_shift($https_urls);

					} else {
						$base = array_shift($urls);

					}

					//
					// append a slash if there isn't one already
					//
					if (1 != preg_match('/\/$/', $base)) $base .= '/';

					//
					// send redirect, preserving any query parameters
					//
					$HTTP->redirect(sprintf('%s%s/%s%s', $base, $type, $object, (empty($_GET) ? '' : '?'.http_build_query($_GET))));

					//
					// and we're done!
					//
				}
			}
		}
	}
}

/**
* function used to sort values by weight
* @param array $a array($weight, $value)
* @param array $b array($weight, $value)
* @return integer -1, 0 or +1
*/
function weighted_sort($a, $b) {
	if ($a[0] == $b[0]) {
		return 0;

	} elseif ($a[0] < $b[0]) {
		return -1;

	} else {
		return 1;

	}
}

/**
* send an RDAP error back to the client
* @param int $code HTTP error code (e.g. 400, 404, etc)
* @param string error message
*/
function rdap_error($code, $msg) {
    global $HTTP;
    $HTTP->status($code, $msg);
    $HTTP->header('Content-Type', 'application/rdap+json');
    echo json_encode([
        'rdapConformance' => ['rdap_level_0'],
        'lang' => 'en',
        'errorCode' => intval($code),
        'title' => $msg,
        'notices' => [
            [
                'title' => 'Terms of Use',
                'description' => [
                    'For more information about this service, please see https://about.rdap.org.',
                ],
                'links' => [
                    [
                        'rel' => 'about',
                        'href' => 'https://about.rdap.org',
                        'title' => 'https://about.rdap.org',
                        'type' => 'text/html',
                    ]
                ]
            ]
        ]
    ]);
    exit;
}
