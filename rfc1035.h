// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "serialization.h"

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace RFC1035 // https://datatracker.ietf.org/doc/html/rfc1035
{
  // https://datatracker.ietf.org/doc/html/rfc1035#section-3.1

  static constexpr size_t MAX_LABEL_SIZE = 63;

  class Label
  {
  public:
    Label() {}

    Label(const std::string& s)
    {
      if (s.size() > MAX_LABEL_SIZE)
        throw std::runtime_error("invalid label size (string)");

      data = {s.data(), s.data() + s.size()};
    }

    Label(const std::vector<uint8_t>& bytes, size_t& pos)
    {
      if (
        pos >= bytes.size() || pos + bytes[pos] >= bytes.size() ||
        bytes[pos] > MAX_LABEL_SIZE)
        throw std::runtime_error("invalid label size (bytes)");

      data.resize(bytes[pos]);
      for (size_t i = 0; i < bytes[pos]; i++)
      {
        data[i] = bytes[pos + 1 + i];
      }
      pos += data.size() + 1;
    }

    bool empty() const
    {
      return data.empty();
    }

    size_t size() const
    {
      return data.size();
    }

    void put(std::vector<uint8_t>& r) const
    {
      r.push_back(data.size());
      r.insert(r.end(), data.begin(), data.end());
    }

    operator std::string() const
    {
      return std::string(data.data(), data.data() + data.size());
    }

    uint8_t operator[](size_t i) const
    {
      return data[i];
    }

  protected:
    std::vector<uint8_t> data;
  };

  inline bool operator==(const RFC1035::Label& x, const RFC1035::Label& y)
  {
    if (x.size() != y.size())
      return false;

    for (size_t i = 1; i < x.size(); i++)
      if (std::tolower(x[i]) != std::tolower(y[i]))
        return false;

    return true;
  }

  inline bool operator<(const RFC1035::Label& x, const RFC1035::Label& y)
  {
    if (x.size() < y.size())
      return true;
    else if (x.size() > y.size())
      return false;
    else
      for (size_t i = 1; i < x.size(); i++)
        if (std::tolower(x[i]) < std::tolower(y[i]))
          return true;
    return false;
  }

  static constexpr size_t MAX_NAME_SIZE = 255;

  class Name
  {
  public:
    std::vector<Label> labels;

    Name()
    {
      labels.push_back(Label());
    }

    Name(const std::string& s)
    {
      std::vector<std::string> tokens;
      std::istringstream f(s);
      std::string tmp;
      size_t total_size = 0;
      while (std::getline(f, tmp, '.'))
      {
        labels.push_back(Label(tmp));
        total_size += labels.back().size();
        if (total_size > MAX_NAME_SIZE)
          throw std::runtime_error("excessive name length");
      }
      if (s.back() == '.')
        labels.push_back(Label());
    }

    Name(const std::vector<uint8_t>& bytes, size_t& pos, size_t num_labels)
    {
      parse_bytes(bytes, pos, num_labels);
    }

    Name(const std::vector<uint8_t>& bytes, size_t num_labels)
    {
      size_t pos = 0;
      parse_bytes(bytes, pos, num_labels);
    }

    Name(const Name& prefix, const Name& suffix)
    {
      labels = prefix.labels;
      for (const auto& l : suffix.labels)
        labels.push_back(l);
    }

    void put(std::vector<uint8_t>& r) const
    {
      for (const auto& label : labels)
        label.put(r);
    }

    bool is_absolute() const
    {
      return labels.back().empty();
    }

    operator std::string() const
    {
      std::string r;
      bool first = true;
      for (const auto& l : labels)
      {
        if (first)
          first = false;
        else
          r += ".";
        r += l;
      }
      return r;
    }

    bool starts_with(const Name& prefix) const
    {
      if (prefix.labels.size() > labels.size())
        return false;
      size_t sz = prefix.labels.size();
      if (prefix.labels.back().empty())
        sz--;
      for (size_t i = 0; i < sz; i++)
        if (labels[i] != prefix.labels[i])
          return false;
      return true;
    }

    bool ends_with(const Name& suffix) const
    {
      if (suffix.labels.size() > labels.size())
        return false;
      size_t sz = suffix.labels.size();
      for (size_t i = 0; i < sz; i++)
        if (labels[labels.size() - i - 1] != suffix.labels[sz - i - 1])
          return false;
      return true;
    }

    void strip_suffix(const Name& suffix)
    {
      if (ends_with(suffix))
        labels.resize(labels.size() - suffix.labels.size());
    }

    Name operator+(const Name& other) const
    {
      Name r;
      r.labels = labels;
      r.labels.insert(labels.end(), other.labels.begin(), other.labels.end());
      return r;
    }

    Name& operator+=(const Name& other)
    {
      labels.insert(labels.end(), other.labels.begin(), other.labels.end());
      return *this;
    }

  protected:
    void parse_bytes(
      const std::vector<uint8_t>& bytes, size_t& pos, size_t num_labels)
    {
      size_t total_size = 0;
      do
      {
        labels.push_back(Label(bytes, pos));
        total_size += labels.back().size();
        if (total_size > MAX_NAME_SIZE)
          throw std::runtime_error("excessive name length");
      } while (labels.back().size() > 0 && pos < bytes.size() &&
               labels.size() < num_labels);
    }
  };

  inline bool operator==(const RFC1035::Name& x, const RFC1035::Name& y)
  {
    if (x.labels.size() != y.labels.size())
      return false;

    for (size_t i = 0; i < x.labels.size(); i++)
      if (x.labels[i] != y.labels[i])
        return false;

    return true;
  }

  inline bool operator<(const RFC1035::Name& x, const RFC1035::Name& y)
  {
    if (x.labels.size() < y.labels.size())
      return true;
    else if (x.labels.size() > y.labels.size())
      return false;

    auto tit = x.labels.begin();
    auto oit = y.labels.begin();

    while (tit != x.labels.end() && oit != y.labels.begin())
    {
      if (*tit != *oit)
        return *tit < *oit;
      tit++;
      oit++;
    }

    return false;
  }
}

template <>
inline void put(const RFC1035::Name& name, std::vector<uint8_t>& r)
{
  name.put(r);
}

namespace RFC1035
{
  // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
  enum class Type : uint16_t
  {
    A = 1, // a host address
    NS = 2, // an authoritative name server
    MD = 3, // a mail destination (Obsolete - use MX)
    MF = 4, // a mail forwarder (Obsolete - use MX)
    CNAME = 5, // the canonical name for an alias
    SOA = 6, // marks the start of a zone of authority
    MB = 7, // a mailbox domain name (EXPERIMENTAL)
    MG = 8, // a mail group member (EXPERIMENTAL)
    MR = 9, // a mail rename domain name (EXPERIMENTAL)
    NULL_ = 10, // a null RR (EXPERIMENTAL)
    WKS = 11, // a well known service description
    PTR = 12, // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX = 15, // mail exchange
    TXT = 16, // text strings
  };

  // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
  enum class QType : uint16_t
  {
    AXFR = 252, // A request for a transfer of an entire zone
    MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    ASTERISK = 255, // A request for all records
  };

}
template <>
inline void put(const RFC1035::Type& x, std::vector<uint8_t>& r)
{
  put(static_cast<uint16_t>(x), r);
}

template <>
inline void put(const RFC1035::QType& x, std::vector<uint8_t>& r)
{
  put(static_cast<uint16_t>(x), r);
}

namespace RFC1035
{
  // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
  enum Class : uint16_t
  {
    IN = 1, // the Internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some
            // obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4, // Hesiod [Dyer 87]
  };

  // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
  enum QClass : uint16_t
  {
    ASTERISK = 255 // any class
  };

  inline bool operator==(const RFC1035::Class& x, const RFC1035::QClass& y)
  {
    return static_cast<uint8_t>(x) == static_cast<uint8_t>(y);
  }

  inline bool operator==(const RFC1035::Type& x, const RFC1035::QType& y)
  {
    return static_cast<uint8_t>(x) == static_cast<uint8_t>(y);
  }

}

template <>
inline void put(const RFC1035::Class& x, std::vector<uint8_t>& r)
{
  put(static_cast<uint16_t>(x), r);
}

template <>
inline void put(const RFC1035::QClass& x, std::vector<uint8_t>& r)
{
  put(static_cast<uint16_t>(x), r);
}

namespace RFC1035
{

  // https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1
  // Same as https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3 ?
  struct ResourceRecord
  {
    /// A domain name to which this resource record pertains.
    Name name;

    /// Two octets containing one of the RR type codes.  This field specifies
    /// the meaning of the data in the RDATA field.
    Type type;

    /// Two octets which specify the class of the data in the RDATA field.
    Class class_;

    /// A 32 bit unsigned integer that specifies the time interval (in
    /// seconds) that the resource record may be cached before it should be
    /// discarded. Zero values are interpreted to mean that the RR can only be
    /// used for the transaction in progress, and should not be cached.
    uint32_t ttl = 0;

    /// An unsigned 16 bit integer that specifies the length in octets of the
    /// RDATA field.
    uint16_t rdlength = 0;

    /// A variable length string of octets that describes the resource. The
    /// format of this information varies according to the TYPE and CLASS of
    /// the resource record. For example, the if the TYPE is A and the CLASS
    /// is IN, the RDATA field is a 4 octet ARPA Internet address.
    std::vector<uint8_t> rdata;

    ResourceRecord() = default;

    ResourceRecord(
      const Name& name,
      Type type,
      Class class_,
      uint32_t ttl,
      const std::vector<uint8_t>& rdata) :
      name(name),
      type(type),
      class_(class_),
      ttl(ttl),
      rdata(rdata)
    {
      if (rdata.size() > (1 << 16))
        throw std::runtime_error("excessive data");
      rdlength = rdata.size();
    }

    ResourceRecord(const std::vector<uint8_t>& bytes, size_t& pos)
    {
      uint8_t len = get<uint8_t>(bytes, pos);
      name = Name(bytes, pos);
      type = static_cast<Type>(get<uint16_t>(bytes, pos));
      class_ = static_cast<Class>(get<uint16_t>(bytes, pos));
      ttl = get<uint32_t>(bytes, pos);
      rdata = get<uint8_t, uint16_t>(bytes, pos);
      rdlength = rdata.size();
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r;
      put(type, r);
      put(class_, r);
      put(ttl, r);
      put(rdata, r);
      return r;
    }
  };

  // https://datatracker.ietf.org/doc/html/rfc1035#section-4

  enum OPCode : uint8_t
  {
    /// A standard query (QUERY)
    STANDARD = 0,

    /// An inverse query (IQUERY)
    INVERSE = 1,

    /// A server status request (STATUS)
    STATUS = 2,
  };

  enum ResponseCode : uint8_t
  {
    /// No error condition
    NO_ERROR = 0,

    /// Format error - The name server was unable to interpret the query.
    FORMAT = 1,

    /// Server failure - The name server was unable to process this query due
    /// to a problem with the name server.
    SERVER_FAILURE = 2,

    /// Name Error - Meaningful only for responses from an authoritative name
    /// server, this code signifies that the domain name referenced in the
    /// query does not exist.
    NAME_ERROR = 3,

    /// Not Implemented - The name server does not support the requested kind
    /// of query.
    NOT_IMPLEMENTED = 4,

    /// Refused - The name server refuses to perform the specified operation
    /// for policy reasons.  For example, a name server may not wish to
    /// provide the information to the particular requester, or a name server
    /// may not wish to perform a particular operation (e.g., zone transfer)
    /// for particular data.
    REFUSED = 5,
  };

  // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
  struct Header
  {
    /// A 16 bit identifier assigned by the program that generates any kind of
    /// query.  This identifier is copied the corresponding reply and can be
    /// used by the requester to match up replies to outstanding queries.
    uint16_t id = 0;

    /// A one bit field that specifies whether this message is a query (0), or
    /// a response (1).
    bool qr = false;

    /// A four bit field that specifies kind of query in this message. This
    /// value is set by the originator of a query and copied into the
    /// response.
    OPCode opcode : 4 = OPCode::STANDARD;

    /// Authoritative Answer
    bool aa = false;

    /// TrunCation
    bool tc = false;

    /// Recursion Desired
    bool rd = false;

    /// Recursion Available
    bool ra = false;

    /// Reserved for future use.  Must be zero in all queries and responses.
    unsigned z : 3 = 0;

    /// Response code - this 4 bit field is set as part of responses.
    ResponseCode rcode : 4 = ResponseCode::NO_ERROR;

    /// An unsigned 16 bit integer specifying the number of entries in the
    /// question section.
    uint16_t qdcount = 0;

    /// An unsigned 16 bit integer specifying the number of resource records
    /// in the answer section.
    uint16_t ancount = 0;

    /// An unsigned 16 bit integer specifying the number of name server
    /// resource records in the authority records section.
    uint16_t nscount = 0;

    /// An unsigned 16 bit integer specifying the number of resource records
    /// in the additional records section.
    uint16_t arcount = 0;

    Header() = default;

    Header(const std::vector<uint8_t>& bytes, size_t& pos)
    {
      id = get<uint16_t>(bytes, pos);
      uint8_t qr_opcode_aa_tc_rd = get<uint16_t>(bytes, pos);
      qr = (qr_opcode_aa_tc_rd & 0x80) != 0;
      opcode = static_cast<OPCode>((qr_opcode_aa_tc_rd & 0x78) >> 3);
      if (opcode > 2)
      {
        throw std::runtime_error("invalid message opcode");
      }
      aa = (qr_opcode_aa_tc_rd & 0x04) != 0;
      tc = (qr_opcode_aa_tc_rd & 0x02) != 0;
      rd = (qr_opcode_aa_tc_rd & 0x01) != 0;
      uint8_t ra_z_rcode = get<uint8_t>(bytes, pos);
      ra = (ra_z_rcode & 0x80) != 0;
      z = 0;
      rcode = static_cast<ResponseCode>(ra_z_rcode & 0x0F);
      if (rcode > 5)
      {
        throw std::runtime_error("invalid message rcode");
      }
      qdcount = get<uint16_t>(bytes, pos);
      ancount = get<uint16_t>(bytes, pos);
      nscount = get<uint16_t>(bytes, pos);
      arcount = get<uint16_t>(bytes, pos);
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r;
      put(id, r);
      uint8_t qr_opcode_aa_tc_rd = ((uint8_t)qr) << 7 | ((uint8_t)opcode) << 3 |
        ((uint8_t)aa) << 2 | ((uint8_t)tc) << 1 | ((uint8_t)rd);
      uint8_t ra_z_rcode = ((uint8_t)ra) << 7 | ((uint8_t)rcode);
      put(qr_opcode_aa_tc_rd << 8 | ra_z_rcode, r);
      put(qdcount, r);
      put(ancount, r);
      put(nscount, r);
      put(arcount, r);
      return r;
    }
  };

  // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
  struct Question
  {
    /// A domain name represented as a sequence of labels, where each label
    /// consists of a length octet followed by that number of octets.  The
    /// domain name terminates with the zero length octet for the null label
    /// of the root.  Note that this field may be an odd number of octets; no
    /// padding is used.
    Name qname;

    /// A two octet code which specifies the type of the query. The values for
    /// this field include all codes valid for a TYPE field, together with
    /// some more general codes which can match more than one type of RR.
    QType qtype;

    /// A two octet code that specifies the class of the query. For example,
    /// the QCLASS field is IN for the Internet.
    QClass qclass;

    Question() = default;

    Question(const std::vector<uint8_t>& bytes, size_t& pos)
    {
      uint8_t len = get<uint8_t>(bytes, pos);
      qname = Name(bytes, pos);
      qtype = static_cast<QType>(get<uint16_t>(bytes, pos));
      qclass = static_cast<QClass>(get<uint16_t>(bytes, pos));
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r;
      put(qname, r);
      put(qtype, r);
      put(qclass, r);
      return r;
    }
  };

  // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1
  class Message
  {
  public:
    Message() = default;

    Message(const std::vector<uint8_t>& bytes)
    {
      size_t pos = 0;
      header = Header(bytes, pos);

      questions = get_n<Question>(bytes, pos, header.qdcount);
      answers = get_n<ResourceRecord>(bytes, pos, header.ancount);
      authorities = get_n<ResourceRecord>(bytes, pos, header.nscount);
      additionals = get_n<ResourceRecord>(bytes, pos, header.arcount);
    }

    ~Message() {}

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r = header;
      put(questions, r);
      put(answers, r);
      put(authorities, r);
      put(additionals, r);
      return r;
    }

    Header header;
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;
  };

  class RDataFormat
  {
  public:
    RDataFormat() {}
    virtual operator std::vector<uint8_t>() const = 0;
    virtual operator std::string() const = 0;
  };

  class A : public RDataFormat
  {
  public:
    std::array<uint8_t, 4> address;

    A(const std::string& data)
    {
      std::vector<std::string> tokens;
      std::istringstream f(data);
      std::string tmp;
      size_t total_size = 0;
      int i = 0;
      while (std::getline(f, tmp, '.'))
      {
        auto st = std::stoi(tmp);
        if (st > 0xFF)
          throw std::runtime_error("invalid IPv4 address");
        address[i++] = st;
        if (i > 4)
          throw std::runtime_error("excess tokens in IPv4 address");
      }
    }

    A(const std::vector<uint8_t>& data)
    {
      if (data.size() != 4)
        throw std::runtime_error("invalid rdata for A record");
      for (size_t i = 0; i < address.size(); i++)
        address[i] = data[i];
    }

    virtual operator std::vector<uint8_t>() const override
    {
      return {address.begin(), address.end()};
    }

    virtual operator std::string() const override
    {
      return std::to_string(address[0]) + "." + std::to_string(address[1]) +
        "." + std::to_string(address[2]) + "." + std::to_string(address[3]);
    }
  };

  class NS : public RDataFormat
  {
  public:
    Name nsdname;

    NS(const std::string& data)
    {
      nsdname = data;
    }

    NS(const std::vector<uint8_t>& data)
    {
      size_t pos = 0;
      nsdname = Name(data, pos);
    }

    virtual operator std::vector<uint8_t>() const override
    {
      std::vector<uint8_t> r;
      nsdname.put(r);
      return r;
    }

    virtual operator std::string() const override
    {
      return nsdname;
    }
  };

  class CNAME : public RDataFormat
  {
  public:
    Name cname;

    CNAME(const std::string& data)
    {
      cname = data;
    }

    virtual operator std::vector<uint8_t>() const override
    {
      std::vector<uint8_t> r;
      cname.put(r);
      return r;
    }

    virtual operator std::string() const override
    {
      return cname;
    }
  };

  class TXT : public RDataFormat
  {
  public:
    std::string txt_data;

    TXT(const std::string& data)
    {
      txt_data = data;
    }

    virtual operator std::vector<uint8_t>() const override
    {
      return {txt_data.data(), txt_data.data() + txt_data.size()};
    }

    virtual operator std::string() const override
    {
      return txt_data;
    }
  };

} // namespace RFC1035
