import 'dart:convert';
import 'dart:developer';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:encrypt/encrypt.dart';
import 'package:map_launcher/src/models.dart';
import 'package:pointycastle/asymmetric/api.dart';
import 'package:yandex_sign/yandex_sign.dart';

class Utils {
  static String? enumToString(o) {
    if (o == null) return null;
    return o.toString().split('.').last;
  }

  static T enumFromString<T>(Iterable<T> values, String? value) {
    return values
        .firstWhere((type) => type.toString().split('.').last == value);
  }

  static String? nullOrValue(dynamic nullable, String value) {
    if (nullable == null) return null;
    return value;
  }

  static String buildUrl({
    required String url,
    required Map<String, String?> queryParams,
  }) {
    return queryParams.entries.fold('$url?', (dynamic previousValue, element) {
      if (element.value == null || element.value == '') {
        return previousValue;
      }
      return '$previousValue&${element.key}=${element.value}';
    }).replaceFirst('&', '');
  }

  static String getAmapDirectionsMode(DirectionsMode? directionsMode) {
    switch (directionsMode) {
      case DirectionsMode.driving:
        return '0';
      case DirectionsMode.transit:
        return '1';
      case DirectionsMode.walking:
        return '2';
      case DirectionsMode.bicycling:
        return '3';
      default:
        return '0';
    }
  }

  static String getBaiduDirectionsMode(DirectionsMode? directionsMode) {
    switch (directionsMode) {
      case DirectionsMode.driving:
        return 'driving';
      case DirectionsMode.transit:
        return 'transit';
      case DirectionsMode.walking:
        return 'walking';
      case DirectionsMode.bicycling:
        return 'riding';
      default:
        return 'driving';
    }
  }

  static String getMapsMeDirectionsMode(DirectionsMode directionsMode) {
    switch (directionsMode) {
      case DirectionsMode.driving:
        return 'vehicle';
      case DirectionsMode.transit:
        return 'transit';
      case DirectionsMode.walking:
        return 'pedestrian';
      case DirectionsMode.bicycling:
        return 'bicycle';
      default:
        return 'vehicle';
    }
  }

  static String getYandexMapsDirectionsMode(DirectionsMode? directionsMode) {
    switch (directionsMode) {
      case DirectionsMode.driving:
        return 'auto';
      case DirectionsMode.transit:
        return 'mt';
      case DirectionsMode.walking:
        return 'pd';
      case DirectionsMode.bicycling:
        return 'auto';
      default:
        return 'auto';
    }
  }

  static String getDoubleGisDirectionsMode(DirectionsMode? directionsMode) {
    switch (directionsMode) {
      case DirectionsMode.driving:
        return 'car';
      case DirectionsMode.transit:
        return 'bus';
      case DirectionsMode.walking:
        return 'pedestrian';
      default:
        return 'auto';
    }
  }

  static String getTencentDirectionsMode(DirectionsMode? directionsMode) {
    switch (directionsMode) {
      case DirectionsMode.driving:
        return 'drive';
      case DirectionsMode.transit:
        return 'bus';
      case DirectionsMode.walking:
        return 'walk';
      case DirectionsMode.bicycling:
        return 'bike';
      default:
        return 'auto';
    }
  }

  static String getRSASignature(String input, String key) {
    final privateKey = RSAKeyParser().parse(key) as RSAPrivateKey;

    final signer = Signer(RSASigner(RSASignDigest.SHA256, privateKey: privateKey));
    log('OLOLO RSAKeyParser ${Uri.encodeComponent(signer.sign(input).base64)}');

    return Uri.encodeComponent(signer.sign(input).base64);
  }
}

/// RSA PEM parser.
class RSAKeyParser {
  /// Parses the PEM key no matter it is public or private, it will figure it out.
  RSAAsymmetricKey parse(String key) {
    final rows = key.split(RegExp(r'\r\n?|\n'));
    final header = rows.first;

    if (header == '-----BEGIN RSA PUBLIC KEY-----') {
      return _parsePublic(_parseSequence(rows));
    }

    if (header == '-----BEGIN PUBLIC KEY-----') {
      return _parsePublic(_pkcs8PublicSequence(_parseSequence(rows)));
    }

    if (header == '-----BEGIN RSA PRIVATE KEY-----') {
      return _parsePrivate(_parseSequence(rows));
    }

    if (header == '-----BEGIN PRIVATE KEY-----') {
      return _parsePrivate(_pkcs8PrivateSequence(_parseSequence(rows)));
    }

    throw FormatException('Unable to parse key, invalid format.', header);
  }

  RSAAsymmetricKey _parsePublic(ASN1Sequence sequence) {
    final modulus = (sequence.elements[0] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;

    return RSAPublicKey(modulus!, exponent!);
  }

  RSAAsymmetricKey _parsePrivate(ASN1Sequence sequence) {
    final modulus = (sequence.elements[1] as ASN1Integer).valueAsBigInteger;
    final exponent = (sequence.elements[3] as ASN1Integer).valueAsBigInteger;
    final p = (sequence.elements[4] as ASN1Integer).valueAsBigInteger;
    final q = (sequence.elements[5] as ASN1Integer).valueAsBigInteger;

    return RSAPrivateKey(modulus!, exponent!, p, q);
  }

  ASN1Sequence _parseSequence(List<String> rows) {
    final keyText = rows
        .skipWhile((row) => row.startsWith('-----BEGIN'))
        .takeWhile((row) => !row.startsWith('-----END'))
        .map((row) => row.trim())
        .join('');

    final keyBytes = Uint8List.fromList(base64.decode(keyText));
    final asn1Parser = ASN1Parser(keyBytes);

    return asn1Parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PublicSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements[1];
    final bytes = bitString.valueBytes().sublist(1);
    final parser = ASN1Parser(Uint8List.fromList(bytes));

    return parser.nextObject() as ASN1Sequence;
  }

  ASN1Sequence _pkcs8PrivateSequence(ASN1Sequence sequence) {
    final ASN1Object bitString = sequence.elements[2];
    final bytes = bitString.valueBytes();
    final parser = ASN1Parser(bytes);

    return parser.nextObject() as ASN1Sequence;
  }
}