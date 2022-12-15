#define _HAS_ITERATOR_DEBUGGING 0

/*++
  Copyright (c) Microsoft Corporation

  This hash template is borrowed from Microsoft Z3
  (https://github.com/Z3Prover/z3).

  Simple implementation of bucket-list hash tables conforming roughly
  to SGI hash_map and hash_set interfaces, though not all members are
  implemented.

  These hash tables have the property that insert preserves iterators
  and references to elements.

  This package lives in namespace hash_space. Specializations of
  class "hash" should be made in this namespace.

  --*/

#pragma once

#ifndef HASH_H
#define HASH_H

#ifdef _WINDOWS
#pragma warning(disable:4267)
#endif

#include <string>
#include <vector>
#include <map>
#include <iterator>
#include <fstream>

namespace hash_space {

  unsigned string_hash(const char * str, unsigned length, unsigned init_value);

  template <typename T> class hash {
  public:
    size_t operator()(const T &s) const {
      return s.__hash();
    }
  };

  template <>
  class hash<int> {
  public:
    size_t operator()(const int &s) const {
      return s;
    }
  };

  template <>
  class hash<long long> {
  public:
    size_t operator()(const long long &s) const {
      return s;
    }
  };

  template <>
  class hash<unsigned> {
  public:
    size_t operator()(const unsigned &s) const {
      return s;
    }
  };

  template <>
  class hash<unsigned long long> {
  public:
    size_t operator()(const unsigned long long &s) const {
      return s;
    }
  };

  template <>
  class hash<bool> {
  public:
    size_t operator()(const bool &s) const {
      return s;
    }
  };

  template <>
  class hash<std::string> {
  public:
    size_t operator()(const std::string &s) const {
      return string_hash(s.c_str(), (unsigned)s.size(), 0);
    }
  };

  template <>
  class hash<std::pair<int,int> > {
  public:
    size_t operator()(const std::pair<int,int> &p) const {
      return p.first + p.second;
    }
  };

  template <typename T>
  class hash<std::vector<T> > {
  public:
    size_t operator()(const std::vector<T> &p) const {
      hash<T> h;
      size_t res = 0;
      for (unsigned i = 0; i < p.size(); i++)
	res += h(p[i]);
      return res;
    }
  };

  template <typename K, typename V>
  class hash<std::map<K,V> > {
  public:
    size_t operator()(const std::map<K,V> &p) const {
      hash<K> hk;
      hash<V> hv;
      size_t res = 0;
      for (typename std::map<K,V>::const_iterator it = p.begin(), en = p.end(); it != en; ++it)
	res += hk(it->first) + hv(it->second);
      return res;
    }
  };

  template <class T>
  class hash<std::pair<T *, T *> > {
  public:
    size_t operator()(const std::pair<T *,T *> &p) const {
      return (size_t)p.first + (size_t)p.second;
    }
  };

  template <class T>
  class hash<T *> {
  public:
    size_t operator()(T * const &p) const {
      return (size_t)p;
    }
  };

  enum { num_primes = 29 };

  static const unsigned long primes[num_primes] =
    {
      7ul,
      53ul,
      97ul,
      193ul,
      389ul,
      769ul,
      1543ul,
      3079ul,
      6151ul,
      12289ul,
      24593ul,
      49157ul,
      98317ul,
      196613ul,
      393241ul,
      786433ul,
      1572869ul,
      3145739ul,
      6291469ul,
      12582917ul,
      25165843ul,
      50331653ul,
      100663319ul,
      201326611ul,
      402653189ul,
      805306457ul,
      1610612741ul,
      3221225473ul,
      4294967291ul
    };

  inline unsigned long next_prime(unsigned long n) {
    const unsigned long* to = primes + (int)num_primes;
    for(const unsigned long* p = primes; p < to; p++)
      if(*p >= n) return *p;
    return primes[num_primes-1];
  }

  template<class Value, class Key, class HashFun, class GetKey, class KeyEqFun>
  class hashtable
  {
  public:

    typedef Value &reference;
    typedef const Value &const_reference;
    
    struct Entry
    {
      Entry* next;
      Value val;
      
      Entry(const Value &_val) : val(_val) {next = 0;}
    };
    

    struct iterator
    {      
      Entry* ent;
      hashtable* tab;

      typedef std::forward_iterator_tag iterator_category;
      typedef Value value_type;
      typedef std::ptrdiff_t difference_type;
      typedef size_t size_type;
      typedef Value& reference;
      typedef Value* pointer;

      iterator(Entry* _ent, hashtable* _tab) : ent(_ent), tab(_tab) { }

      iterator() { }

      Value &operator*() const { return ent->val; }

      Value *operator->() const { return &(operator*()); }

      iterator &operator++() {
	Entry *old = ent;
	ent = ent->next;
	if (!ent) {
	  size_t bucket = tab->get_bucket(old->val);
	  while (!ent && ++bucket < tab->buckets.size())
	    ent = tab->buckets[bucket];
	}
	return *this;
      }

      iterator operator++(int) {
	iterator tmp = *this;
	operator++();
	return tmp;
      }


      bool operator==(const iterator& it) const { 
	return ent == it.ent;
      }

      bool operator!=(const iterator& it) const {
	return ent != it.ent;
      }
    };

    struct const_iterator
    {      
      const Entry* ent;
      const hashtable* tab;

      typedef std::forward_iterator_tag iterator_category;
      typedef Value value_type;
      typedef std::ptrdiff_t difference_type;
      typedef size_t size_type;
      typedef const Value& reference;
      typedef const Value* pointer;

      const_iterator(const Entry* _ent, const hashtable* _tab) : ent(_ent), tab(_tab) { }

      const_iterator() { }

      const Value &operator*() const { return ent->val; }

      const Value *operator->() const { return &(operator*()); }

      const_iterator &operator++() {
	const Entry *old = ent;
	ent = ent->next;
	if (!ent) {
	  size_t bucket = tab->get_bucket(old->val);
	  while (!ent && ++bucket < tab->buckets.size())
	    ent = tab->buckets[bucket];
	}
	return *this;
      }

      const_iterator operator++(int) {
	const_iterator tmp = *this;
	operator++();
	return tmp;
      }


      bool operator==(const const_iterator& it) const { 
	return ent == it.ent;
      }

      bool operator!=(const const_iterator& it) const {
	return ent != it.ent;
      }
    };

  private:

    typedef std::vector<Entry*> Table;

    Table buckets;
    size_t entries;
    HashFun hash_fun ;
    GetKey get_key;
    KeyEqFun key_eq_fun;
    
  public:

    hashtable(size_t init_size) : buckets(init_size,(Entry *)0) {
      entries = 0;
    }
    
    hashtable(const hashtable& other) {
      dup(other);
    }

    hashtable& operator= (const hashtable& other) {
      if (&other != this)
	dup(other);
      return *this;
    }

    ~hashtable() {
      clear();
    }

    size_t size() const { 
      return entries;
    }

    bool empty() const { 
      return size() == 0;
    }

    void swap(hashtable& other) {
      buckets.swap(other.buckets);
      std::swap(entries, other.entries);
    }
    
    iterator begin() {
      for (size_t i = 0; i < buckets.size(); ++i)
	if (buckets[i])
	  return iterator(buckets[i], this);
      return end();
    }
    
    iterator end() { 
      return iterator(0, this);
    }

    const_iterator begin() const {
      for (size_t i = 0; i < buckets.size(); ++i)
	if (buckets[i])
	  return const_iterator(buckets[i], this);
      return end();
    }
    
    const_iterator end() const { 
      return const_iterator(0, this);
    }
    
    size_t get_bucket(const Value& val, size_t n) const {
      return hash_fun(get_key(val)) % n;
    }
    
    size_t get_key_bucket(const Key& key) const {
      return hash_fun(key) % buckets.size();
    }

    size_t get_bucket(const Value& val) const {
      return get_bucket(val,buckets.size());
    }

    Entry *lookup(const Value& val, bool ins = false)
    {
      resize(entries + 1);

      size_t n = get_bucket(val);
      Entry* from = buckets[n];
      
      for (Entry* ent = from; ent; ent = ent->next)
	if (key_eq_fun(get_key(ent->val), get_key(val)))
	  return ent;
      
      if(!ins) return 0;

      Entry* tmp = new Entry(val);
      tmp->next = from;
      buckets[n] = tmp;
      ++entries;
      return tmp;
    }

    Entry *lookup_key(const Key& key) const
    {
      size_t n = get_key_bucket(key);
      Entry* from = buckets[n];
      
      for (Entry* ent = from; ent; ent = ent->next)
	if (key_eq_fun(get_key(ent->val), key))
	  return ent;
      
      return 0;
    }

    const_iterator find(const Key& key) const {
      return const_iterator(lookup_key(key),this);
    }

    iterator find(const Key& key) {
      return iterator(lookup_key(key),this);
    }

    std::pair<iterator,bool> insert(const Value& val){
      size_t old_entries = entries;
      Entry *ent = lookup(val,true);
      return std::pair<iterator,bool>(iterator(ent,this),entries > old_entries);
    }
    
    iterator insert(const iterator &it, const Value& val){
      Entry *ent = lookup(val,true);
      return iterator(ent,this);
    }

    size_t erase(const Key& key)
    {
      Entry** p = &(buckets[get_key_bucket(key)]);
      size_t count = 0;
      while(*p){
	Entry *q = *p;
	if (key_eq_fun(get_key(q->val), key)) {
	  ++count;
	  *p = q->next;
	  delete q;
	}
	else
	  p = &(q->next);
      }
      entries -= count;
      return count;
    }

    void resize(size_t new_size) {
      const size_t old_n = buckets.size();
      if (new_size <= old_n) return;
      const size_t n = next_prime(new_size);
      if (n <= old_n) return;
      Table tmp(n, (Entry*)(0));
      for (size_t i = 0; i < old_n; ++i) {
	Entry* ent = buckets[i];
	while (ent) {
	  size_t new_bucket = get_bucket(ent->val, n);
	  buckets[i] = ent->next;
	  ent->next = tmp[new_bucket];
	  tmp[new_bucket] = ent;
	  ent = buckets[i];
	}
      }
      buckets.swap(tmp);
    }
    
    void clear()
    {
      for (size_t i = 0; i < buckets.size(); ++i) {
	for (Entry* ent = buckets[i]; ent != 0;) {
	  Entry* next = ent->next;
	  delete ent;
	  ent = next;
	}
	buckets[i] = 0;
      }
      entries = 0;
    }

    void dup(const hashtable& other)
    {
      clear();
      buckets.resize(other.buckets.size());
      for (size_t i = 0; i < other.buckets.size(); ++i) {
	Entry** to = &buckets[i];
	for (Entry* from = other.buckets[i]; from; from = from->next)
	  to = &((*to = new Entry(from->val))->next);
      }
      entries = other.entries;
    }
  };

  template <typename T> 
  class equal {
  public:
    bool operator()(const T& x, const T &y) const {
      return x == y;
    }
  };

  template <typename T>
  class identity {
  public:
    const T &operator()(const T &x) const {
      return x;
    }
  };

  template <typename T, typename U>
  class proj1 {
  public:
    const T &operator()(const std::pair<T,U> &x) const {
      return x.first;
    }
  };

  template <typename Element, class HashFun = hash<Element>, 
	    class EqFun = equal<Element> >
  class hash_set
    : public hashtable<Element,Element,HashFun,identity<Element>,EqFun> {

  public:

    typedef Element value_type;

    hash_set()
      : hashtable<Element,Element,HashFun,identity<Element>,EqFun>(7) {}
  };

  template <typename Key, typename Value, class HashFun = hash<Key>, 
	    class EqFun = equal<Key> >
  class hash_map
    : public hashtable<std::pair<Key,Value>,Key,HashFun,proj1<Key,Value>,EqFun> {

  public:

    hash_map()
      : hashtable<std::pair<Key,Value>,Key,HashFun,proj1<Key,Value>,EqFun>(7) {}

    Value &operator[](const Key& key) {
      std::pair<Key,Value> kvp(key,Value());
      return 
	hashtable<std::pair<Key,Value>,Key,HashFun,proj1<Key,Value>,EqFun>::
        lookup(kvp,true)->val.second;
    }
  };

  template <typename D,typename R>
  class hash<hash_map<D,R> > {
  public:
    size_t operator()(const hash_map<D,R> &p) const {
      hash<D > h1;
      hash<R > h2;
      size_t res = 0;
            
      for (typename hash_map<D,R>::const_iterator it=p.begin(), en=p.end(); it!=en; ++it)
	res += (h1(it->first)+h2(it->second));
      return res;
    }
  };

  template <typename D,typename R>
  inline bool operator ==(const hash_map<D,R> &s, const hash_map<D,R> &t){
    for (typename hash_map<D,R>::const_iterator it=s.begin(), en=s.end(); it!=en; ++it) {
      typename hash_map<D,R>::const_iterator it2 = t.find(it->first);
      if (it2 == t.end() || !(it->second == it2->second)) return false;
    }
    for (typename hash_map<D,R>::const_iterator it=t.begin(), en=t.end(); it!=en; ++it) {
      typename hash_map<D,R>::const_iterator it2 = s.find(it->first);
      if (it2 == t.end() || !(it->second == it2->second)) return false;
    }
    return true;
  }
}
#endif
typedef std::string __strlit;
extern std::ofstream __ivy_out;
void __ivy_exit(int);

template <typename D, typename R>
struct thunk {
  virtual R operator()(const D &) = 0;
  int ___ivy_choose(int rng,const char *name,int id) {
    return 0;
  }
};
template <typename D, typename R, class HashFun = hash_space::hash<D> >
struct hash_thunk {
  thunk<D,R> *fun;
  hash_space::hash_map<D,R,HashFun> memo;
  hash_thunk() : fun(0) {}
  hash_thunk(thunk<D,R> *fun) : fun(fun) {}
  ~hash_thunk() {
    //        if (fun)
    //            delete fun;
  }
  R &operator[](const D& arg){
    std::pair<typename hash_space::hash_map<D,R>::iterator,bool> foo = memo.insert(std::pair<D,R>(arg,R()));
    R &res = foo.first->second;
    if (foo.second && fun)
      res = (*fun)(arg);
    return res;
  }
};

#include <netinet/tcp.h>
#include <list>
#include <semaphore.h>

class tcp_listener;   // class of threads that listen for connections
class tcp_callbacks;  // class holding callbacks to ivy

// A tcp_config maps endpoint ids to IP addresses and ports.

class tcp_config {
public:
  // get the address and port from the endpoint id
  virtual void get(int id, unsigned long &inetaddr, unsigned long &inetport);

  // get the endpoint id from the address and port
  virtual int rev(unsigned long inetaddr, unsigned long inetport);
};

class tcp_queue;


#include <map>
class sec_timer;
    

class reader;
class timer;

class craq_system {
public:
  typedef craq_system ivy_class;

  std::vector<std::string> __argv;
#ifdef _WIN32
  void *mutex;  // forward reference to HANDLE
#else
  pthread_mutex_t mutex;
#endif
  void __lock();
  void __unlock();

#ifdef _WIN32
  std::vector<HANDLE> thread_ids;

#else
  std::vector<pthread_t> thread_ids;

#endif
  void install_reader(reader *);
  void install_thread(reader *);
  void install_timer(timer *);
  virtual ~craq_system();
  std::vector<int> ___ivy_stack;
  int ___ivy_choose(int rng,const char *name,int id);
  virtual void ivy_assert(bool,const char *){}
  virtual void ivy_assume(bool,const char *){}
  virtual void ivy_check_progress(int,int){}
  struct msg_num__iter__t {
    bool is_end;
    unsigned val;
    size_t __hash() const { size_t hv = 0;
      hv += hash_space::hash<bool>()(is_end);
      hv += hash_space::hash<unsigned>()(val);
      return hv;
    }
  };
  struct key_tups__t {
    unsigned x;
    unsigned y;
    size_t __hash() const { size_t hv = 0;
      hv += hash_space::hash<unsigned>()(x);
      hv += hash_space::hash<unsigned>()(y);
      return hv;
    }
  };
  enum query_type{read,write};
  struct query {
    unsigned qkey;
    query_type qtype;
    __strlit qvalue;
    unsigned qsrc;
    unsigned qid;
    unsigned qvnum;
    size_t __hash() const { size_t hv = 0;
      hv += hash_space::hash<unsigned>()(qkey);
      hv += hash_space::hash<int>()(qtype);
      hv += hash_space::hash<__strlit>()(qvalue);
      hv += hash_space::hash<unsigned>()(qsrc);
      hv += hash_space::hash<unsigned>()(qid);
      hv += hash_space::hash<unsigned>()(qvnum);
      return hv;
    }
  };
  enum msg_type{msg_type__request,msg_type__reply,msg_type__inquire,msg_type__inform,msg_type__commitAck,msg_type__ack};
  struct msg {
    msg_type t;
    unsigned src;
    unsigned msgnum;
    query body;
    size_t __hash() const { size_t hv = 0;
      hv += hash_space::hash<int>()(t);
      hv += hash_space::hash<unsigned>()(src);
      hv += hash_space::hash<unsigned>()(msgnum);
      hv += hash_space::hash<query>()(body);
      return hv;
    }
  };
  unsigned node__size;
  hash_thunk<unsigned,bool> system__server__dBitMap;
  unsigned system__server__req_no;
  unsigned system__server__ver_no;
  hash_thunk<unsigned,unsigned> system__server__highestVersion;
  bool net__proc__isup[32];
  hash_thunk<key_tups__t,__strlit> system__server__mvMap;
  unsigned me;
  bool _generating;
  bool net__proc__pend[32];
  unsigned trans__recv_seq[32];
  unsigned trans__send_seq[32];
  int net__proc__sock[32];
  hash_thunk<unsigned,__strlit> system__server__viewMap;
  long long __CARD__node;
  long long __CARD__ver_num__t;
  long long __CARD__key;
  long long __CARD__net__tcp__socket;
  long long __CARD__msg_num__t;
  long long __CARD__req_num__t;
  long long __CARD__value;
  virtual unsigned __num0();
  virtual unsigned node__max();

  tcp_listener *net__tcp__impl__rdr;             // the listener task
  tcp_callbacks *net__tcp__impl__cb;             // the callbacks to ivy
  hash_space::hash_map<int,tcp_queue *> net__tcp__impl__send_queue;   // queues of blocked packets, per socket


  tcp_config *the_tcp_config;  // the current configurations

  // Get the current TCP configuration. If none, create a default one.

  tcp_config *get_tcp_config() {
    if (!the_tcp_config) 
      the_tcp_config = new tcp_config();
    return the_tcp_config; 
  }

  // Set the current TCP configuration. This is called by the runtime environment.

  void set_tcp_config(tcp_config *conf) {
    the_tcp_config = conf;
  }

  std::map<unsigned,msg> trans__mq__imap__impl__s[32];
  sec_timer *trans__timer__impl__tmr[32];
  craq_system(unsigned node__size, unsigned me);
  void __init();
  virtual void ext__trans__handle_request(const query& rq);
  virtual void ext__system__server__get(unsigned k);
  virtual unsigned ext__ver_num__next(unsigned seq);
  virtual void ext__trans__mq__imap__set(unsigned prm__D, unsigned nkey, const msg& v);
  virtual void ext__trans__handle_commitAck(const query& rq);
  virtual void ext__net__tcp__failed(int s);
  virtual void net__tcp__impl__handle_fail(int s);
  virtual unsigned ext__node__prev(unsigned x);
  virtual void ext__net__recv(const msg& v);
  virtual void ext__trans__handle_reply(const query& rq);
  virtual void ext__trans__timer__timeout(unsigned prm__D);
  virtual void ext__trans__handle_inquire(const query& rq);
  virtual unsigned ext__msg_num__next(unsigned seq);
  virtual bool ext__trans__mq__empty(unsigned prm__D);
  virtual void ext__trans__send_inquire(unsigned dst, const query& rq);
  virtual void ext__trans__send_commitAck(unsigned dst, const query& rq);
  virtual void ext__trans__mq__delete_all(unsigned prm__D, unsigned seq);
  virtual bool ext__net__tcp__send(int s, const msg& p);
  virtual unsigned ext__req_num__next(unsigned seq);
  virtual void trans__timer__impl__handle_timeout(unsigned prm__D);
  virtual void ext__trans__send_inform(unsigned dst, const query& rq);
  virtual void ext__trans__mq__imap__erase(unsigned prm__D, const msg_num__iter__t& lo, const msg_num__iter__t& hi);
  virtual int ext__net__tcp__connect(unsigned other);
  virtual void ext__net__tcp__accept(int s, unsigned other);
  virtual void ext__net__tcp__recv(int s, const msg& p);
  virtual msg ext__trans__mq__pick_one(unsigned prm__D);
  virtual void ext__system__server__set(unsigned k, __strlit d);
  virtual void ext__spec__commit(const query& req, const query& repl);
  virtual void net__tcp__impl__handle_accept(int s, unsigned other);
  virtual void ext__trans__send_reply(unsigned dst, const query& rq);
  virtual void imp__system__server__answer(unsigned k, __strlit v, unsigned id);
  virtual void ext__net__send(unsigned dst, const msg& v);
  virtual void ext__trans__handle_inform(const query& rq);
  virtual unsigned ext__node__next(unsigned x);
  virtual msg_num__iter__t ext__trans__mq__imap__lub(unsigned prm__D, const msg_num__iter__t& it);
  virtual void net__tcp__impl__handle_recv(int s, const msg& x);
  virtual void ext__trans__mq__enqueue(unsigned prm__D, msg m);
  virtual msg ext__trans__mq__imap__get(unsigned prm__D, unsigned k, const msg& def);
  virtual void ext__trans__send_request(unsigned dst, const query& rq);
  virtual msg_num__iter__t ext__msg_num__iter__create(unsigned x);
  virtual void ext__system__server__answer(unsigned k, __strlit v, unsigned id);
  virtual void ext__net__tcp__close(int s);
  virtual void net__tcp__impl__handle_connected(int s);
  virtual void ext__net__tcp__connected(int s);
  void __tick(int timeout);
};
inline bool operator ==(const craq_system::msg_num__iter__t &s, const craq_system::msg_num__iter__t &t){
  return ((s.is_end == t.is_end) && (s.val == t.val));
}
inline bool operator ==(const craq_system::key_tups__t &s, const craq_system::key_tups__t &t){
  return ((s.x == t.x) && (s.y == t.y));
}
inline bool operator ==(const craq_system::query &s, const craq_system::query &t){
  return ((s.qkey == t.qkey) && (s.qtype == t.qtype) && (s.qvalue == t.qvalue) && (s.qsrc == t.qsrc) && (s.qid == t.qid) && (s.qvnum == t.qvnum));
}
inline bool operator ==(const craq_system::msg &s, const craq_system::msg &t){
  return ((s.t == t.t) && (s.src == t.src) && (s.msgnum == t.msgnum) && (s.body == t.body));
}
