// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "serialization.h"
#include "small_vector.h"

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
      data = small_vector<uint8_t>(s.size(), (uint8_t*)s.data());
    }

    Label(const std::span<const uint8_t>& bytes, size_t& pos)
    {
      if (pos >= bytes.size())
        throw std::runtime_error("invalid label size (position)");

      uint8_t flags = bytes[pos] >> 6;
      uint8_t sz = bytes[pos] & 0x3F;

      if (pos + sz >= bytes.size() || sz > MAX_LABEL_SIZE)
        throw std::runtime_error(
          "invalid label size (" + std::to_string(sz) + " bytes)");

      data = small_vector<uint8_t>(bytes[pos]);
      for (size_t i = 0; i < bytes[pos]; i++)
      {
        auto index = pos + 1 + i;
        if (index >= bytes.size())
          throw std::runtime_error("not enough label data");
        data[i] = bytes[index];
      }
      pos += data.size() + 1;
    }

    Label(const std::vector<uint8_t>& bytes, size_t& pos) :
      Label(std::span<const uint8_t>(bytes), pos)
    {}

    template <typename T>
    Label(const small_vector<T>& bytes, size_t& pos)
    {
      if (pos >= bytes.size())
        throw std::runtime_error("invalid label size (position)");

      uint8_t flags = bytes[pos] >> 6;
      uint8_t sz = bytes[pos] & 0x3F;

      if (pos + sz >= bytes.size() || bytes[pos] > MAX_LABEL_SIZE)
        throw std::runtime_error("invalid label size (small_vector)");

      data = small_vector<uint8_t>(bytes[pos]);
      for (size_t i = 0; i < bytes[pos]; i++)
      {
        auto index = pos + 1 + i;
        if (index >= bytes.size())
          throw std::runtime_error("not enough label data");
        data[i] = bytes.at(index);
      }

      pos += data.size() + 1;
    }

    Label(const Label& other)
    {
      data = other.data;
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
      for (uint8_t i = 0; i < data.size(); i++)
        r.push_back(data[i]);
    }

    operator std::string() const
    {
      std::string r;
      for (uint8_t i = 0; i < data.size(); i++)
        r += (char)data[i];
      return r;
    }

    uint8_t operator[](size_t i) const
    {
      return data[i];
    }

    Label& operator=(const Label& other)
    {
      data = other.data;
      return *this;
    }

    operator small_vector<uint8_t>() const
    {
      return data;
    }

    void lower()
    {
      for (size_t i = 0; i < size(); i++)
        data[i] = std::tolower(data[i]);
    }

    Label lowered() const
    {
      Label r;
      r.data = data;
      for (size_t i = 0; i < size(); i++)
        r.data[i] = std::tolower(data[i]);
      return r;
    }

    bool is_wildcard() const
    {
      return data.size() == 1 && data[0] == '*';
    }

  protected:
    small_vector<uint8_t> data;
  };

  inline bool operator==(const RFC1035::Label& x, const RFC1035::Label& y)
  {
    if (x.size() != y.size())
      return false;

    for (size_t i = 0; i < x.size(); i++)
      if (std::tolower(x[i]) != std::tolower(y[i]))
        return false;

    return true;
  }

  static constexpr size_t MAX_NAME_SIZE = 255;

  class Name
  {
  public:
    std::vector<Label> labels;

    Name() {}

    Name(const std::string& s)
    {
      if (s != ".")
      {
        std::stringstream f(s);
        std::string tmp;
        size_t total_size = 0;
        while (std::getline(f, tmp, '.'))
        {
          labels.push_back(Label(tmp));
          total_size += labels.back().size();
          if (total_size > MAX_NAME_SIZE)
            throw std::runtime_error("excessive name length");
        }
      }
      if (s.back() == '.')
        labels.push_back(Label());
    }

    Name(const std::span<const uint8_t>& bytes, size_t& pos)
    {
      parse_bytes(bytes, pos);
    }

    Name(const std::vector<uint8_t>& bytes, size_t& pos) :
      Name(std::span<const uint8_t>(bytes), pos)
    {}

    Name(const std::vector<uint8_t>& bytes, size_t& pos, uint8_t num_labels)
    {
      parse_bytes(bytes, pos, num_labels);
    }

    Name(const std::vector<uint8_t>& bytes)
    {
      size_t pos = 0;
      parse_bytes(bytes, pos);
    }

    Name(const small_vector<uint16_t>& bytes, size_t& pos)
    {
      parse_bytes(bytes, pos);
    }

    Name(const small_vector<uint16_t>& bytes, size_t& pos, uint8_t num_labels)
    {
      parse_bytes(bytes, pos, num_labels);
    }

    Name(const small_vector<uint16_t>& bytes)
    {
      size_t pos = 0;
      parse_bytes(bytes, pos);
    }

    Name(const Name& prefix, const Name& suffix)
    {
      labels = prefix.labels;
      for (const auto& l : suffix.labels)
        labels.push_back(l);
    }

    Name(const std::vector<Label>& labels)
    {
      this->labels = labels;
    }

    Name(std::vector<Label>&& labels) : labels(std::move(labels)) {}

    Name(const std::span<const Label>& lspan)
    {
      labels.reserve(lspan.size());
      for (const auto& l : lspan)
        labels.push_back(l);
    }

    void put(std::vector<uint8_t>& r) const
    {
      for (const auto& label : labels)
        label.put(r);
    }

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r;
      put(r);
      return r;
    }

    operator small_vector<uint16_t, small_vector<uint8_t, uint8_t>>() const
    {
      small_vector<uint16_t, small_vector<uint8_t>> r(labels.size());
      uint16_t i = 0;
      for (const auto& l : labels)
        r[i++] = (small_vector<uint8_t>)l;
      return r;
    }

    operator small_vector<uint16_t>() const
    {
      small_vector<uint16_t> r(byte_size());
      uint16_t p = 0;
      for (const auto& l : labels)
      {
        r[p++] = l.size();
        if (p == 0)
          throw std::runtime_error("name too long for small_vector");
        for (uint8_t i = 0; i < l.size(); i++)
        {
          r[p++] = l[i];
          if (p == 0)
            throw std::runtime_error("name too long for small_vector");
        }
      }
      return r;
    }

    uint16_t byte_size() const
    {
      uint16_t sz = 0;
      for (const auto& l : labels)
        sz += l.size() + 1;
      return sz;
    }

    /// Indicates whether the name is absolute (fully qualified).
    bool is_absolute() const
    {
      return labels.size() > 0 && labels.back().empty();
    }

    bool is_root() const
    {
      return labels.size() == 1 && labels.back().empty();
    }

    bool empty() const
    {
      return labels.empty();
    }

    /// Converts the name to its string representation.
    operator std::string() const
    {
      if (is_root())
        return ".";

      std::string r;
      bool first = true;
      for (const auto& l : labels)
      {
        if (first)
          first = false;
        else
          r += ".";
        r += (std::string)l;
      }
      return r;
    }

    std::string unterminated() const
    {
      std::string r = *this;
      while (r.back() == '.')
        r.pop_back();
      return r;
    }

    Name terminated() const
    {
      Name t = *this;
      if (t.labels.size() == 0 || !t.labels.back().empty())
        t.labels.push_back(Label());
      return t;
    }

    /// Indicates whether the name starts with the given prefix.
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

    Name lowered() const
    {
      std::vector<Label> llabels;
      for (const auto& l : labels)
        llabels.push_back(l.lowered());
      return Name(llabels);
    }

    void lower()
    {
      for (auto& l : labels)
        l.lower();
    }

    Name operator+(const Name& other) const
    {
      std::vector<Label> lbls = labels;
      if (is_absolute())
        lbls.pop_back();
      for (const auto& l : other.labels)
        lbls.push_back(l);
      return Name(lbls);
    }

    Name& operator+=(const Name& other)
    {
      if (is_absolute())
        labels.pop_back();
      for (const auto& l : other.labels)
        labels.push_back(l);
      return *this;
    }

    Name parent() const
    {
      if (labels.size() == 0)
        throw std::runtime_error("root does not have a parent");
      return Name(std::vector<Label>(labels.begin() + 1, labels.end()));
    }

  protected:
    void parse_bytes(
      const std::span<const uint8_t>& bytes,
      size_t& pos,
      uint8_t num_labels = 0xFF)
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

    void parse_bytes(
      const std::vector<uint8_t>& bytes, size_t& pos, uint8_t num_labels = 0xFF)
    {
      parse_bytes(std::span<const uint8_t>(bytes), pos, num_labels);
    }

    void parse_bytes(
      const small_vector<uint16_t>& bytes,
      size_t& pos,
      uint8_t num_labels = 0xFF)
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
}

template <>
inline void put(const RFC1035::Name& name, std::vector<uint8_t>& r)
{
  if (!name.is_absolute())
    throw std::runtime_error("cannot serialize relative names");
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

  inline std::map<Type, std::string> type_string_map = {
    {Type::A, "A"},
    {Type::NS, "NS"},
    {Type::MD, "MD"},
    {Type::MF, "MF"},
    {Type::CNAME, "CNAME"},
    {Type::SOA, "SOA"},
    {Type::MB, "MB"},
    {Type::MG, "MG"},
    {Type::MR, "MR"},
    {Type::NULL_, "NULL"},
    {Type::WKS, "WKS"},
    {Type::PTR, "PTR"},
    {Type::HINFO, "HINFO"},
    {Type::MINFO, "MINFO"},
    {Type::MX, "MX"},
    {Type::TXT, "TXT"},
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
    /// The domain name/owner to which this resource record pertains.
    Name name;

    /// Two octets containing one of the RR type codes.  This field specifies
    /// the meaning of the data in the RDATA field.
    uint16_t type;

    /// Two octets which specify the class of the data in the RDATA field.
    uint16_t class_;

    /// A 32 bit unsigned integer that specifies the time interval (in
    /// seconds) that the resource record may be cached before it should be
    /// discarded. Zero values are interpreted to mean that the RR can only be
    /// used for the transaction in progress, and should not be cached.
    uint32_t ttl = 0;

    /// rdlength: An unsigned 16 bit integer that specifies the length in octets
    /// of the RDATA field.
    /// rdata: A variable length string of octets that
    /// describes the resource. The format of this information varies according
    /// to the TYPE and CLASS of the resource record. For example, the if the
    /// TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA
    /// Internet address.
    small_vector<uint16_t> rdata;

    ResourceRecord() = default;

    ResourceRecord(
      const Name& name,
      uint16_t type,
      uint16_t class_,
      uint32_t ttl,
      const small_vector<uint16_t>& rdata) :
      name(name),
      type(type),
      class_(class_),
      ttl(ttl),
      rdata(rdata)
    {}

    ResourceRecord(const std::span<const uint8_t>& bytes, size_t& pos)
    {
      name = Name(bytes, pos);
      type = get<uint16_t>(bytes, pos);
      class_ = get<uint16_t>(bytes, pos);
      ttl = get<uint32_t>(bytes, pos);
      rdata = small_vector<uint16_t, uint8_t>(bytes, pos);
    }

    ResourceRecord(const std::vector<uint8_t>& bytes, size_t& pos) :
      ResourceRecord(std::span<const uint8_t>(bytes), pos)
    {}

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r;
      put(name, r);
      put(type, r);
      put(class_, r);
      put(ttl, r);
      rdata.put(r);
      return r;
    }

    bool operator==(const ResourceRecord& other) const = default;
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

    Header(const std::span<const uint8_t>& bytes, size_t& pos)
    {
      id = get<uint16_t>(bytes, pos);
      uint8_t qr_opcode_aa_tc_rd = get<uint8_t>(bytes, pos);
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

    Header(const std::vector<uint8_t>& bytes, size_t& pos) :
      Header(std::span<const uint8_t>(bytes), pos)
    {}

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r;
      put(id, r);
      uint8_t qr_opcode_aa_tc_rd = ((uint8_t)qr) << 7 | ((uint8_t)opcode) << 3 |
        ((uint8_t)aa) << 2 | ((uint8_t)tc) << 1 | ((uint8_t)rd);
      uint8_t ra_z_rcode = ((uint8_t)ra) << 7 | ((uint8_t)rcode);
      put((uint16_t)(qr_opcode_aa_tc_rd << 8 | ra_z_rcode), r);
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

    Question(const std::span<const uint8_t>& bytes, size_t& pos)
    {
      qname = Name(bytes, pos);
      if (!qname.is_absolute())
        throw std::runtime_error("unexpected relative name in question");
      qtype = static_cast<QType>(get<uint16_t>(bytes, pos));
      qclass = static_cast<QClass>(get<uint16_t>(bytes, pos));
    }

    Question(const std::vector<uint8_t>& bytes, size_t& pos) :
      Question(std::span<const uint8_t>(bytes), pos)
    {}

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

    Message(const std::span<const uint8_t>& bytes, size_t& pos)
    {
      header = Header(bytes, pos);

      questions = get_n<Question>(bytes, pos, header.qdcount);
      answers = get_n<ResourceRecord>(bytes, pos, header.ancount);
      authorities = get_n<ResourceRecord>(bytes, pos, header.nscount);
      additionals = get_n<ResourceRecord>(bytes, pos, header.arcount);
    }

    Message(const std::vector<uint8_t>& bytes, size_t& pos) :
      Message(std::span<const uint8_t>(bytes), pos)
    {}

    ~Message() {}

    operator std::vector<uint8_t>() const
    {
      std::vector<uint8_t> r = header;
      put_n(questions, r, questions.size());
      put_n(answers, r, answers.size());
      put_n(authorities, r, authorities.size());
      put_n(additionals, r, additionals.size());
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
    virtual ~RDataFormat() {}
    virtual operator small_vector<uint16_t>() const = 0;
    virtual operator std::string() const = 0;

    bool operator<(const RDataFormat& other) const
    {
      return (small_vector<uint16_t>)(*this) < (small_vector<uint16_t>)other;
    }

    bool operator==(const RDataFormat& other) const
    {
      return (small_vector<uint16_t>)(*this) == (small_vector<uint16_t>)other;
    }

    bool operator!=(const RDataFormat& other) const
    {
      return !((*this) == other);
    }
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

    A(const small_vector<uint16_t>& data)
    {
      if (data.size() != 4)
        throw std::runtime_error("invalid rdata for A record");
      for (size_t i = 0; i < address.size(); i++)
        address[i] = data[i];
    }

    virtual operator small_vector<uint16_t>() const override
    {
      return small_vector<uint16_t>((uint16_t)address.size(), address.data());
    }

    virtual operator std::string() const override
    {
      return std::to_string(address[0]) + "." + std::to_string(address[1]) +
        "." + std::to_string(address[2]) + "." + std::to_string(address[3]);
    }

    virtual ~A() = default;
  };

  class NS : public RDataFormat
  {
  public:
    Name nsdname;

    NS(const Name& n)
    {
      nsdname = n;
    }

    NS(const std::string& data)
    {
      nsdname = data;
    }

    NS(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      nsdname = Name(data, pos);
    }

    virtual operator small_vector<uint16_t>() const override
    {
      return nsdname;
    }

    virtual operator std::string() const override
    {
      return nsdname;
    }

    virtual ~NS() = default;
  };

  class SOA : public RDataFormat
  {
  public:
    Name mname;
    Name rname;
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;

    SOA(const std::string& data)
    {
      std::stringstream s(data);
      std::string tmp;
      s >> tmp;
      mname = Name(tmp);
      if (!mname.is_absolute())
        throw std::runtime_error("invalid SOA record: mname not absolute");
      s >> tmp;
      rname = Name(tmp);
      if (!rname.is_absolute())
        throw std::runtime_error("invalid SOA record: rname not absolute");
      s >> serial;
      s >> refresh;
      s >> retry;
      s >> expire;
      s >> minimum;
    }

    SOA(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      mname = Name(data, pos);
      if (!mname.is_absolute())
        throw std::runtime_error("invalid SOA record: mname not absolute");
      rname = Name(data, pos);
      if (!rname.is_absolute())
        throw std::runtime_error("invalid SOA record: rname not absolute");
      serial = get<uint32_t>(data, pos);
      refresh = get<uint32_t>(data, pos);
      retry = get<uint32_t>(data, pos);
      expire = get<uint32_t>(data, pos);
      minimum = get<uint32_t>(data, pos);
    }

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(mname, r);
      put(rname, r);
      put(serial, r);
      put(refresh, r);
      put(retry, r);
      put(expire, r);
      put(minimum, r);
      return small_vector<uint16_t>(r.size(), r.data());
    }

    virtual operator std::string() const override
    {
      return (std::string)mname + " " + (std::string)rname + " " +
        std::to_string(serial) + " " + std::to_string(refresh) + " " +
        std::to_string(retry) + " " + std::to_string(expire) + " " +
        std::to_string(minimum);
    }

    virtual ~SOA() = default;
  };

  class CNAME : public RDataFormat
  {
  public:
    Name cname;

    CNAME(const std::string& data)
    {
      cname = data;
    }

    CNAME(const small_vector<uint16_t>& data)
    {
      cname = Name(data);
    }

    virtual operator small_vector<uint16_t>() const override
    {
      return cname;
    }

    virtual operator std::string() const override
    {
      return cname;
    }

    virtual ~CNAME() = default;
  };

  class MX : public RDataFormat
  {
  public:
    uint16_t preference;
    Name exchange;

    MX(const std::string& data)
    {
      std::stringstream s(data);
      std::string tmp;
      s >> preference;
      s >> tmp;
      exchange = Name(tmp);
    }

    MX(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      preference = get<uint16_t>(data, pos);
      exchange = Name(data, pos);
    }

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      put(preference, r);
      put(exchange, r);
      return small_vector<uint16_t>((uint16_t)r.size(), (uint8_t*)r.data());
    }

    virtual operator std::string() const override
    {
      return std::to_string(preference) + " " + (std::string)exchange;
    }

    virtual ~MX() = default;
  };

  class TXT : public RDataFormat
  {
  public:
    std::vector<small_vector<uint8_t>> strings;

    TXT(const std::string& data)
    {
      for (size_t i = 0; i < data.size();)
      {
        size_t j = std::min(i + 255, data.size());
        strings.push_back(data.substr(i, j - i));
        i = j;
      }
    }

    TXT(const std::vector<std::string>& data)
    {
      for (const auto& s : data)
      {
        if (s.size() > 255)
          throw std::runtime_error("excessive string length");
        strings.push_back(s);
      }
    }

    TXT(const small_vector<uint16_t>& data)
    {
      size_t pos = 0;
      while (pos < data.size())
      {
        strings.push_back(small_vector<uint8_t>(data, pos));
      }
    }

    virtual operator small_vector<uint16_t>() const override
    {
      std::vector<uint8_t> r;
      for (const auto& s : strings)
      {
        if (s.size() > 255)
          throw std::runtime_error("excessive string length");
        s.put(r);
        if (r.size() > 65535)
          throw std::runtime_error("excessive TXT rdata length");
      }
      return small_vector<uint16_t>((uint16_t)r.size(), (uint8_t*)r.data());
    }

    virtual operator std::string() const override
    {
      std::string r;
      for (const auto& s : strings)
      {
        if (!r.empty())
          r += " ";
        // auto ss = ds::to_hex(s);
        std::string ss((const char*)s.raw(), s.size());
        r += std::string("\"") + ss + "\"";
      }
      return r;
    }

    virtual ~TXT() = default;
  };

} // namespace RFC1035
