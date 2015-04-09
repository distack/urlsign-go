#!/usr/bin/env ruby

require "uri"
require "openssl"
require "base64"

class UrlSigner
  def initialize(hex_key)
    @key = [hex_key].pack("H*")
  end

  def sign(url)
    if url.opaque
      raise "can't sign or verify opaque URL"
    end

    chunks = [url.scheme, "#{url.host}:#{url.port}", url.path, url.query, url.userinfo].compact
    digest = OpenSSL::Digest.new("sha512")

    rawsig    = OpenSSL::HMAC.digest(digest, @key, chunks.join)
    signature = Base64.urlsafe_encode64(rawsig)

    if url.query
      q = URI.decode_www_form(url.query)
    else
      q = []
    end

    q << ["_signature", signature]
    q.sort_by! { |(n,v)| n }

    new_url = url.dup
    new_url.query = URI.encode_www_form(q)
    new_url
  end
end

if $0 == __FILE__
  puts UrlSigner.new(ARGV[0]).sign(URI.parse(ARGV[1]))
end
