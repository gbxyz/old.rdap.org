<?php

// RDAP.org main request handler
// Copyright 2018 Gavin Brown <gavin.brown@uk.com>

// CRC is a foundation library available from CentralNic:
require(dirname(__DIR__).'/CRC/CRC.php');

$HTTP = new CRC_HTTP;
$UA = new CRC_HTTPClient;

$HANDLER = new CRC_ErrorHandler(NULL, 'gavin@tau.uk.com', 'localhost');

// Allow cross-origin requests:
$HTTP->header('Access-Control-Allow-Origin', '*');

// we don't have PATH_INFO so remove any query string from REQUEST_URI:
$path = preg_replace('/\?.*$/', '', $_SERVER['REQUEST_URI']);

if ('/' == $path) {
	$HTTP->status(301, 'Moved Permanently');
	$HTTP->redirect('https://about.rdap.org/');

} else {
	$parts = preg_split('/\//', $path, 2, PREG_SPLIT_NO_EMPTY);
	if (2 != count($parts)) {
		$HTTP->status(400, 'Bad Request, queries must take the form /<type>/<handle>');

	} else {
		// extract object type and object handle from the path
		list($type, $object) = $parts;

		if (!in_array($type, array('domain', 'ip', 'autnum'))) {
			// unknown object type
			$HTTP->status(400, sprintf("Bad Request, unsupported object type '%s'", $type));

		} else {
			if ('domain' == $type) {
				$url = 'https://data.iana.org/rdap/dns.json';

			} elseif ('ip' == $type) {
				// turn $object into a CRC_IP object
				try {
					$object = CRC_IP::fromString($object);

				} catch (Exception $e) {
					$HTTP->status(400, 'Invalid format for IP query');

				}

				$url = (AF_INET == $object->family() ? 'https://data.iana.org/rdap/ipv4.json' : 'https://data.iana.org/rdap/ipv6.json');

			} elseif ('autnum' == $type) {
				$object = intval($object);

				$url = 'https://data.iana.org/rdap/asn.json';
			}

			$json = $UA->mirror($url);
			if (PEAR::isError($json)) {
				$HTTP->status(504, 'Unable to retrieve bootstrap file from IANA');

			} else {
				$registry = json_decode($json);

				// scan through each service in the registry, putting any which match into
				// $matches, along with a corresponding "weight", so they can be sorted
				// by weight to find the closest-matching service:
				$matches = array();
				foreach ($registry->services as $service) {
					list($values, $urls) = $service;
					foreach ($values as $value) {
						if ('autnum' == $type) {
							if (intval($value) == $object) {
								// exact match, weight is zero
								$matches[] = array(0, $urls);
								break 2;

							} elseif (1 == preg_match('/^(\d+)-(\d+)$/', $value, $numbers)) {
								$min = intval($numbers[1]);
								$max = intval($numbers[2]);

								if ($object >= $min && $object <= $max) {
									// enclosing match, weight is the width of the range
									$matches[] = array(($max - $min), $urls);
								}

							}

						} elseif ('ip' == $type) {
							try {
								$net = CRC_IP::fromString($value);

								if ($net->equals($object)) {
									// exact match, weight is zero
									$matches[] = array(0, $urls);
									break 2;

								} elseif ($net->contains($object)) {
									// enclosing match, weight is the length of the suffix
									$matches[] = array($net->bits() - $net->getPrefix(), $urls);

								}

							} catch (Exception $e) {
								continue;

							}

						} elseif ('domain' == $type) {
							if (lc($value) == lc($object)) {
								// exact match, weight is zero
								$matches[] = array(0, $urls);
								break 2;

							} elseif (1 == preg_match(sprintf('/\.%s/i', preg_quote($value)), $object)) {
								// enclosing match, weight is the length of the value
								$matches[] = array(strlen($value), $urls);

							}
						}
					}
				}

				if (count($matches) < 1) {
					$HTTP->status(404, sprintf('%s %s not found in IANA boostrap file', $type, $object));

				} else {
					// sort matching services by weight, lowest first
					usort($matches, 'weighted_sort');
					$match = array_shift($matches);
					$urls = $match[1];

					// prefer HTTPS URLs to other URLs
					$https_urls = preg_grep('/^https:/', $urls);
					if (count($https_urls) > 0) {
						$base = array_shift($https_urls);

					} else {
						$base = array_shift($urls);

					}

					// append a slash if there isn't one already
					if (1 != preg_match('/\/$/', $base)) $base .= '/';

					$HTTP->redirect(sprintf('%s%s/%s', $base, $type, $object));
				}
			}
		}
	}
}

function weighted_sort($a, $b) {
	if ($a[0] == $b[0]) {
		return 0;

	} elseif ($a[0] < $b[0]) {
		return -1;

	} else {
		return 1;

	}
}
