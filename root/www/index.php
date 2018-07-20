<?php

// RDAP.org main request handler
// Copyright 2018 Gavin Brown <gavin.brown@uk.com>

// CRC is a foundation library available from CentralNic:
require(dirname(__DIR__).'/CRC/CRC.php');

$HTTP = new CRC_HTTP;
$UA = new CRC_HTTPClient;

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
		$HTTP->status(400, 'Bad Request: queries must take the form /<type>/<handle>');

	} else {
		// extract object type and object handle from the path
		list($type, $object) = $parts;

		if ('domain' != $type) {
			// unknown object type
			$HTTP->status(400, sprintf("Bad Request: unsupported object type '%s'", $type));

		} elseif (1 != preg_match('/^[a-z0-9\-]{2,}$/', $object)) {
			// invalid syntax
			$HTTP->status(400, 'Bad Request: invalid TLD a-label');

		} else {
			$file = sprintf('%s/etc/%s.json', dirname(__DIR__), $object);
			if (!file_exists($file)) {
				$HTTP->status(400, sprintf("TLD '%s' does not exist", $object));

			} else {
				header('Content-Type: application/rdap+json');
				readfile($file);

			}
		}
	}
}
