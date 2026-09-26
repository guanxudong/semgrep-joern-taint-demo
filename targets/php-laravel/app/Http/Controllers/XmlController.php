<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class XmlController
{
    public function parse(Request $request)
    {
        $data = $request->getContent();
        $root = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT);
        return response()->json(['tag' => $root->getName(), 'text' => (string) $root]);
    }

    public function parseV2(Request $request)
    {
        $data = $request->getContent();
        $root = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NONET);
        return response()->json(['tag' => $root->getName(), 'text' => (string) $root]);
    }
}
