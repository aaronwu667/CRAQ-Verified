#include "craq_system.h"

#include <sstream>
#include <algorithm>

#include <iostream>
#include <stdlib.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>
#include <io.h>
#define isatty _isatty
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> 
#include <sys/select.h>
#include <unistd.h>
#define _open open
#define _dup2 dup2
#endif
#include <string.h>
#include <stdio.h>
#include <string>
#if __cplusplus < 201103L
#else
#include <cstdint>
#endif
typedef craq_system ivy_class;
std::ofstream __ivy_out;
std::ofstream __ivy_modelfile;
void __ivy_exit(int code){exit(code);}

class reader {
public:
    virtual int fdes() = 0;
    virtual void read() = 0;
    virtual void bind() {}
    virtual bool running() {return fdes() >= 0;}
    virtual bool background() {return false;}
    virtual ~reader() {}
};

class timer {
public:
    virtual int ms_delay() = 0;
    virtual void timeout(int) = 0;
    virtual ~timer() {}
};

#ifdef _WIN32
DWORD WINAPI ReaderThreadFunction( LPVOID lpParam ) 
{
    reader *cr = (reader *) lpParam;
    cr->bind();
    while (true)
        cr->read();
    return 0;
} 

DWORD WINAPI TimerThreadFunction( LPVOID lpParam ) 
{
    timer *cr = (timer *) lpParam;
    while (true) {
        int ms = cr->ms_delay();
        Sleep(ms);
        cr->timeout(ms);
    }
    return 0;
} 
#else
void * _thread_reader(void *rdr_void) {
    reader *rdr = (reader *) rdr_void;
    rdr->bind();
    while(rdr->running()) {
        rdr->read();
    }
    delete rdr;
    return 0; // just to stop warning
}

void * _thread_timer( void *tmr_void ) 
{
    timer *tmr = (timer *) tmr_void;
    while (true) {
        int ms = tmr->ms_delay();
        struct timespec ts;
        ts.tv_sec = ms/1000;
        ts.tv_nsec = (ms % 1000) * 1000000;
        nanosleep(&ts,NULL);
        tmr->timeout(ms);
    }
    return 0;
} 
#endif 

void craq_system::install_reader(reader *r) {
    #ifdef _WIN32

        DWORD dummy;
        HANDLE h = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            ReaderThreadFunction,   // thread function name
            r,                      // argument to thread function 
            0,                      // use default creation flags 
            &dummy);                // returns the thread identifier 
        if (h == NULL) {
            std::cerr << "failed to create thread" << std::endl;
            exit(1);
        }
        thread_ids.push_back(h);
    #else
        pthread_t thread;
        int res = pthread_create(&thread, NULL, _thread_reader, r);
        if (res) {
            std::cerr << "failed to create thread" << std::endl;
            exit(1);
        }
        thread_ids.push_back(thread);
    #endif
}      

void craq_system::install_thread(reader *r) {
    install_reader(r);
}

void craq_system::install_timer(timer *r) {
    #ifdef _WIN32

        DWORD dummy;
        HANDLE h = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            TimersThreadFunction,   // thread function name
            r,                      // argument to thread function 
            0,                      // use default creation flags 
            &dummy);                // returns the thread identifier 
        if (h == NULL) {
            std::cerr << "failed to create thread" << std::endl;
            exit(1);
        }
        thread_ids.push_back(h);
    #else
        pthread_t thread;
        int res = pthread_create(&thread, NULL, _thread_timer, r);
        if (res) {
            std::cerr << "failed to create thread" << std::endl;
            exit(1);
        }
        thread_ids.push_back(thread);
    #endif
}      


#ifdef _WIN32
    void craq_system::__lock() { WaitForSingleObject(mutex,INFINITE); }
    void craq_system::__unlock() { ReleaseMutex(mutex); }
#else
    void craq_system::__lock() { pthread_mutex_lock(&mutex); }
    void craq_system::__unlock() { pthread_mutex_unlock(&mutex); }
#endif
struct thunk__net__tcp__impl__handle_accept{
    craq_system *__ivy;
    thunk__net__tcp__impl__handle_accept(craq_system *__ivy): __ivy(__ivy){}
    void operator()(int s, unsigned other) const {
        return __ivy->net__tcp__impl__handle_accept(s,other);
    }
};
struct thunk__net__tcp__impl__handle_connected{
    craq_system *__ivy;
    thunk__net__tcp__impl__handle_connected(craq_system *__ivy): __ivy(__ivy){}
    void operator()(int s) const {
        return __ivy->net__tcp__impl__handle_connected(s);
    }
};
struct thunk__net__tcp__impl__handle_fail{
    craq_system *__ivy;
    thunk__net__tcp__impl__handle_fail(craq_system *__ivy): __ivy(__ivy){}
    void operator()(int s) const {
        return __ivy->net__tcp__impl__handle_fail(s);
    }
};
struct thunk__net__tcp__impl__handle_recv{
    craq_system *__ivy;
    thunk__net__tcp__impl__handle_recv(craq_system *__ivy): __ivy(__ivy){}
    void operator()(int s, craq_system::msg x) const {
        return __ivy->net__tcp__impl__handle_recv(s,x);
    }
};
struct thunk__trans__timer__impl__handle_timeout{
    craq_system *__ivy;
    unsigned prm__D;
    thunk__trans__timer__impl__handle_timeout(craq_system *__ivy, unsigned prm__D): __ivy(__ivy),prm__D(prm__D){}
    void operator()() const {
        return __ivy->trans__timer__impl__handle_timeout(prm__D);
    }
};

/*++
Copyright (c) Microsoft Corporation

This string hash function is borrowed from Microsoft Z3
(https://github.com/Z3Prover/z3). 

--*/


#define mix(a,b,c)              \
{                               \
  a -= b; a -= c; a ^= (c>>13); \
  b -= c; b -= a; b ^= (a<<8);  \
  c -= a; c -= b; c ^= (b>>13); \
  a -= b; a -= c; a ^= (c>>12); \
  b -= c; b -= a; b ^= (a<<16); \
  c -= a; c -= b; c ^= (b>>5);  \
  a -= b; a -= c; a ^= (c>>3);  \
  b -= c; b -= a; b ^= (a<<10); \
  c -= a; c -= b; c ^= (b>>15); \
}

#ifndef __fallthrough
#define __fallthrough
#endif

namespace hash_space {

// I'm using Bob Jenkin's hash function.
// http://burtleburtle.net/bob/hash/doobs.html
unsigned string_hash(const char * str, unsigned length, unsigned init_value) {
    unsigned a, b, c, len;

    /* Set up the internal state */
    len = length;
    a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
    c = init_value;      /* the previous hash value */

    /*---------------------------------------- handle most of the key */
    while (len >= 12) {
        a += reinterpret_cast<const unsigned *>(str)[0];
        b += reinterpret_cast<const unsigned *>(str)[1];
        c += reinterpret_cast<const unsigned *>(str)[2];
        mix(a,b,c);
        str += 12; len -= 12;
    }

    /*------------------------------------- handle the last 11 bytes */
    c += length;
    switch(len) {        /* all the case statements fall through */
    case 11: 
        c+=((unsigned)str[10]<<24);
        __fallthrough;
    case 10: 
        c+=((unsigned)str[9]<<16);
        __fallthrough;
    case 9 : 
        c+=((unsigned)str[8]<<8);
        __fallthrough;
        /* the first byte of c is reserved for the length */
    case 8 : 
        b+=((unsigned)str[7]<<24);
        __fallthrough;
    case 7 : 
        b+=((unsigned)str[6]<<16);
        __fallthrough;
    case 6 : 
        b+=((unsigned)str[5]<<8);
        __fallthrough;
    case 5 : 
        b+=str[4];
        __fallthrough;
    case 4 : 
        a+=((unsigned)str[3]<<24);
        __fallthrough;
    case 3 : 
        a+=((unsigned)str[2]<<16);
        __fallthrough;
    case 2 : 
        a+=((unsigned)str[1]<<8);
        __fallthrough;
    case 1 : 
        a+=str[0];
        __fallthrough;
        /* case 0: nothing left to add */
    }
    mix(a,b,c);
    /*-------------------------------------------- report the result */
    return c;
}

}




struct ivy_value {
    int pos;
    std::string atom;
    std::vector<ivy_value> fields;
    bool is_member() const {
        return atom.size() && fields.size();
    }
};
struct deser_err {
};

struct ivy_ser {
    virtual void  set(long long) = 0;
    virtual void  set(bool) = 0;
    virtual void  setn(long long inp, int len) = 0;
    virtual void  set(const std::string &) = 0;
    virtual void  open_list(int len) = 0;
    virtual void  close_list() = 0;
    virtual void  open_list_elem() = 0;
    virtual void  close_list_elem() = 0;
    virtual void  open_struct() = 0;
    virtual void  close_struct() = 0;
    virtual void  open_field(const std::string &) = 0;
    virtual void  close_field() = 0;
    virtual void  open_tag(int, const std::string &) {throw deser_err();}
    virtual void  close_tag() {}
    virtual ~ivy_ser(){}
};
struct ivy_binary_ser : public ivy_ser {
    std::vector<char> res;
    void setn(long long inp, int len) {
        for (int i = len-1; i >= 0 ; i--)
            res.push_back((inp>>(8*i))&0xff);
    }
    void set(long long inp) {
        setn(inp,sizeof(long long));
    }
    void set(bool inp) {
        set((long long)inp);
    }
    void set(const std::string &inp) {
        for (unsigned i = 0; i < inp.size(); i++)
            res.push_back(inp[i]);
        res.push_back(0);
    }
    void open_list(int len) {
        set((long long)len);
    }
    void close_list() {}
    void open_list_elem() {}
    void close_list_elem() {}
    void open_struct() {}
    void close_struct() {}
    virtual void  open_field(const std::string &) {}
    void close_field() {}
    virtual void  open_tag(int tag, const std::string &) {
        set((long long)tag);
    }
    virtual void  close_tag() {}
};

struct ivy_deser {
    virtual void  get(long long&) = 0;
    virtual void  get(std::string &) = 0;
    virtual void  getn(long long &res, int bytes) = 0;
    virtual void  open_list() = 0;
    virtual void  close_list() = 0;
    virtual bool  open_list_elem() = 0;
    virtual void  close_list_elem() = 0;
    virtual void  open_struct() = 0;
    virtual void  close_struct() = 0;
    virtual void  open_field(const std::string &) = 0;
    virtual void  close_field() = 0;
    virtual int   open_tag(const std::vector<std::string> &) {throw deser_err();}
    virtual void  close_tag() {}
    virtual void  end() = 0;
    virtual ~ivy_deser(){}
};

struct ivy_binary_deser : public ivy_deser {
    std::vector<char> inp;
    int pos;
    std::vector<int> lenstack;
    ivy_binary_deser(const std::vector<char> &inp) : inp(inp),pos(0) {}
    virtual bool more(unsigned bytes) {return inp.size() >= pos + bytes;}
    virtual bool can_end() {return pos == inp.size();}
    void get(long long &res) {
       getn(res,8);
    }
    void getn(long long &res, int bytes) {
        if (!more(bytes))
            throw deser_err();
        res = 0;
        for (int i = 0; i < bytes; i++)
            res = (res << 8) | (((long long)inp[pos++]) & 0xff);
    }
    void get(std::string &res) {
        while (more(1) && inp[pos]) {
//            if (inp[pos] == '"')
//                throw deser_err();
            res.push_back(inp[pos++]);
        }
        if(!(more(1) && inp[pos] == 0))
            throw deser_err();
        pos++;
    }
    void open_list() {
        long long len;
        get(len);
        lenstack.push_back(len);
    }
    void close_list() {
        lenstack.pop_back();
    }
    bool open_list_elem() {
        return lenstack.back();
    }
    void close_list_elem() {
        lenstack.back()--;
    }
    void open_struct() {}
    void close_struct() {}
    virtual void  open_field(const std::string &) {}
    void close_field() {}
    int open_tag(const std::vector<std::string> &tags) {
        long long res;
        get(res);
        if (res >= tags.size())
            throw deser_err();
        return res;
    }
    void end() {
        if (!can_end())
            throw deser_err();
    }
};
struct ivy_socket_deser : public ivy_binary_deser {
      int sock;
    public:
      ivy_socket_deser(int sock, const std::vector<char> &inp)
          : ivy_binary_deser(inp), sock(sock) {}
    virtual bool more(unsigned bytes) {
        while (inp.size() < pos + bytes) {
            int oldsize = inp.size();
            int get = pos + bytes - oldsize;
            get = (get < 1024) ? 1024 : get;
            inp.resize(oldsize + get);
            int newbytes;
	    if ((newbytes = read(sock,&inp[oldsize],get)) < 0)
		 { std::cerr << "recvfrom failed\n"; exit(1); }
            inp.resize(oldsize + newbytes);
            if (newbytes == 0)
                 return false;
        }
        return true;
    }
    virtual bool can_end() {return true;}
};

struct out_of_bounds {
    std::string txt;
    int pos;
    out_of_bounds(int _idx, int pos = 0) : pos(pos){
        std::ostringstream os;
        os << "argument " << _idx+1;
        txt = os.str();
    }
    out_of_bounds(const std::string &s, int pos = 0) : txt(s), pos(pos) {}
};

template <class T> T _arg(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <class T> T __lit(const char *);

template <>
bool _arg<bool>(std::vector<ivy_value> &args, unsigned idx, long long bound) {
    if (!(args[idx].atom == "true" || args[idx].atom == "false") || args[idx].fields.size())
        throw out_of_bounds(idx,args[idx].pos);
    return args[idx].atom == "true";
}

template <>
int _arg<int>(std::vector<ivy_value> &args, unsigned idx, long long bound) {
    std::istringstream s(args[idx].atom.c_str());
    s.unsetf(std::ios::dec);
    s.unsetf(std::ios::hex);
    s.unsetf(std::ios::oct);
    long long res;
    s  >> res;
    // int res = atoi(args[idx].atom.c_str());
    if (bound && (res < 0 || res >= bound) || args[idx].fields.size())
        throw out_of_bounds(idx,args[idx].pos);
    return res;
}

template <>
long long _arg<long long>(std::vector<ivy_value> &args, unsigned idx, long long bound) {
    std::istringstream s(args[idx].atom.c_str());
    s.unsetf(std::ios::dec);
    s.unsetf(std::ios::hex);
    s.unsetf(std::ios::oct);
    long long res;
    s  >> res;
//    long long res = atoll(args[idx].atom.c_str());
    if (bound && (res < 0 || res >= bound) || args[idx].fields.size())
        throw out_of_bounds(idx,args[idx].pos);
    return res;
}

template <>
unsigned long long _arg<unsigned long long>(std::vector<ivy_value> &args, unsigned idx, long long bound) {
    std::istringstream s(args[idx].atom.c_str());
    s.unsetf(std::ios::dec);
    s.unsetf(std::ios::hex);
    s.unsetf(std::ios::oct);
    unsigned long long res;
    s  >> res;
//    unsigned long long res = atoll(args[idx].atom.c_str());
    if (bound && (res < 0 || res >= bound) || args[idx].fields.size())
        throw out_of_bounds(idx,args[idx].pos);
    return res;
}

template <>
unsigned _arg<unsigned>(std::vector<ivy_value> &args, unsigned idx, long long bound) {
    std::istringstream s(args[idx].atom.c_str());
    s.unsetf(std::ios::dec);
    s.unsetf(std::ios::hex);
    s.unsetf(std::ios::oct);
    unsigned res;
    s  >> res;
//    unsigned res = atoll(args[idx].atom.c_str());
    if (bound && (res < 0 || res >= bound) || args[idx].fields.size())
        throw out_of_bounds(idx,args[idx].pos);
    return res;
}


std::ostream &operator <<(std::ostream &s, const __strlit &t){
    s << "\"" << t.c_str() << "\"";
    return s;
}

template <>
__strlit _arg<__strlit>(std::vector<ivy_value> &args, unsigned idx, long long bound) {
    if (args[idx].fields.size())
        throw out_of_bounds(idx,args[idx].pos);
    return args[idx].atom;
}

template <class T> void __ser(ivy_ser &res, const T &inp);

template <>
void __ser<int>(ivy_ser &res, const int &inp) {
    res.set((long long)inp);
}

template <>
void __ser<long long>(ivy_ser &res, const long long &inp) {
    res.set(inp);
}

template <>
void __ser<unsigned long long>(ivy_ser &res, const unsigned long long &inp) {
    res.set((long long)inp);
}

template <>
void __ser<unsigned>(ivy_ser &res, const unsigned &inp) {
    res.set((long long)inp);
}

template <>
void __ser<bool>(ivy_ser &res, const bool &inp) {
    res.set(inp);
}


template <>
void __ser<__strlit>(ivy_ser &res, const __strlit &inp) {
    res.set(inp);
}

template <class T> void __deser(ivy_deser &inp, T &res);

template <>
void __deser<int>(ivy_deser &inp, int &res) {
    long long temp;
    inp.get(temp);
    res = temp;
}

template <>
void __deser<long long>(ivy_deser &inp, long long &res) {
    inp.get(res);
}

template <>
void __deser<unsigned long long>(ivy_deser &inp, unsigned long long &res) {
    long long temp;
    inp.get(temp);
    res = temp;
}

template <>
void __deser<unsigned>(ivy_deser &inp, unsigned &res) {
    long long temp;
    inp.get(temp);
    res = temp;
}

template <>
void __deser<__strlit>(ivy_deser &inp, __strlit &res) {
    inp.get(res);
}

template <>
void __deser<bool>(ivy_deser &inp, bool &res) {
    long long thing;
    inp.get(thing);
    res = thing;
}

void __deser(ivy_deser &inp, std::vector<bool>::reference res) {
    long long thing;
    inp.get(thing);
    res = thing;
}

class gen;

std::ostream &operator <<(std::ostream &s, const craq_system::msg_type &t);
template <>
craq_system::msg_type _arg<craq_system::msg_type>(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <>
void  __ser<craq_system::msg_type>(ivy_ser &res, const craq_system::msg_type&);
template <>
void  __deser<craq_system::msg_type>(ivy_deser &inp, craq_system::msg_type &res);
std::ostream &operator <<(std::ostream &s, const craq_system::query_type &t);
template <>
craq_system::query_type _arg<craq_system::query_type>(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <>
void  __ser<craq_system::query_type>(ivy_ser &res, const craq_system::query_type&);
template <>
void  __deser<craq_system::query_type>(ivy_deser &inp, craq_system::query_type &res);
std::ostream &operator <<(std::ostream &s, const craq_system::key_tups__t &t);
template <>
craq_system::key_tups__t _arg<craq_system::key_tups__t>(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <>
void  __ser<craq_system::key_tups__t>(ivy_ser &res, const craq_system::key_tups__t&);
template <>
void  __deser<craq_system::key_tups__t>(ivy_deser &inp, craq_system::key_tups__t &res);
std::ostream &operator <<(std::ostream &s, const craq_system::msg &t);
template <>
craq_system::msg _arg<craq_system::msg>(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <>
void  __ser<craq_system::msg>(ivy_ser &res, const craq_system::msg&);
template <>
void  __deser<craq_system::msg>(ivy_deser &inp, craq_system::msg &res);
std::ostream &operator <<(std::ostream &s, const craq_system::msg_num__iter__t &t);
template <>
craq_system::msg_num__iter__t _arg<craq_system::msg_num__iter__t>(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <>
void  __ser<craq_system::msg_num__iter__t>(ivy_ser &res, const craq_system::msg_num__iter__t&);
template <>
void  __deser<craq_system::msg_num__iter__t>(ivy_deser &inp, craq_system::msg_num__iter__t &res);
std::ostream &operator <<(std::ostream &s, const craq_system::query &t);
template <>
craq_system::query _arg<craq_system::query>(std::vector<ivy_value> &args, unsigned idx, long long bound);
template <>
void  __ser<craq_system::query>(ivy_ser &res, const craq_system::query&);
template <>
void  __deser<craq_system::query>(ivy_deser &inp, craq_system::query &res);

   // Maximum number of sent packets to queue on a channel. Because TCP also
   // buffers, the total number of untransmitted backets that can back up will be greater
   // than this. This number *must* be at least one to void packet corruption.

   #define MAX_TCP_SEND_QUEUE 16

   struct tcp_mutex {
#ifdef _WIN32
       HANDLE mutex;
       tcp_mutex() { mutex = CreateMutex(NULL,FALSE,NULL); }
       void lock() { WaitForSingleObject(mutex,INFINITE); }
       void unlock() { ReleaseMutex(mutex); }
#else
       pthread_mutex_t mutex;
       tcp_mutex() { pthread_mutex_init(&mutex,NULL); }
       void lock() { pthread_mutex_lock(&mutex); }
       void unlock() { pthread_mutex_unlock(&mutex); }
#endif
   };

   struct tcp_sem {
       sem_t sem;
       tcp_sem() { sem_init(&sem,0,0); }
       void up() {sem_post(&sem); }
       void down() {sem_wait(&sem);}
   };

   class tcp_queue {
       tcp_mutex mutex; 
       tcp_sem sem;
       bool closed;
       bool reported_closed;
       std::list<std::vector<char> > bufs;
    public:
       int other; // only acces while holding lock!
       tcp_queue(int other) : closed(false), reported_closed(false), other(other) {}
       bool enqueue_swap(std::vector<char> &buf) {
           mutex.lock();
           if (closed) {
               mutex.unlock();
               return true;
           }
           if (bufs.size() < MAX_TCP_SEND_QUEUE) {
               bufs.push_back(std::vector<char>());
               buf.swap(bufs.back());
           }
           mutex.unlock();
           sem.up();
           return false;
       }
       bool dequeue_swap(std::vector<char> &buf) {
           while(true) {
               sem.down();
               // std::cout << "DEQUEUEING" << closed << std::endl;
               mutex.lock();
               if (closed) {
                   if (reported_closed) {
                       mutex.unlock();
                       continue;
                   }
                   reported_closed = true;
                   mutex.unlock();
                   // std::cout << "REPORTING CLOSED" << std::endl;
                   return true;
               }
               if (bufs.size() > 0) {
                   buf.swap(bufs.front());
                   bufs.erase(bufs.begin());
                   mutex.unlock();
                   return false;
               }
               mutex.unlock();
            }
       }
       void set_closed(bool report=true) {
           mutex.lock();
           closed = true;
           bufs.clear();
           if (!report)
               reported_closed = true;
           mutex.unlock();
           sem.up();
       }
       void set_open(int _other) {
           mutex.lock();
           closed = false;
           reported_closed = false;
           other = _other;
           mutex.unlock();
           sem.up();
       }
       void wait_open(bool closed_val = false){
           while (true) {
               mutex.lock();
               if (closed == closed_val) {
                   mutex.unlock();
                   return;
               }
               mutex.unlock();
               sem.down();
            }
       }

   };

   // The default configuration gives address 127.0.0.1 and port port_base + id.

    void tcp_config::get(int id, unsigned long &inetaddr, unsigned long &inetport) {
#ifdef _WIN32
            inetaddr = ntohl(inet_addr("127.0.0.1")); // can't send to INADDR_ANY in windows
#else
            inetaddr = INADDR_ANY;
#endif
            inetport = 5990+ id;
    }

    // This reverses the default configuration's map. Note, this is a little dangerous
    // since an attacker could cause a bogus id to be returned. For the moment we have
    // no way to know the correct range of endpoint ids.

    int tcp_config::rev(unsigned long inetaddr, unsigned long inetport) {
        return inetport - 5990; // don't use this for real, it's vulnerable
    }

    // construct a sockaddr_in for a specified process id using the configuration

    void get_tcp_addr(ivy_class *ivy, int my_id, sockaddr_in &myaddr) {
        memset((char *)&myaddr, 0, sizeof(myaddr));
        unsigned long inetaddr;
        unsigned long inetport;
        ivy->get_tcp_config() -> get(my_id,inetaddr,inetport);
        myaddr.sin_family = AF_INET;
        myaddr.sin_addr.s_addr = htonl(inetaddr);
        myaddr.sin_port = htons(inetport);
    }

    // get the process id of a sockaddr_in using the configuration in reverse

    int get_tcp_id(ivy_class *ivy, const sockaddr_in &myaddr) {
       return ivy->get_tcp_config() -> rev(ntohl(myaddr.sin_addr.s_addr), ntohs(myaddr.sin_port));
    }

    // get a new TCP socket

    int make_tcp_socket() {
        int sock = ::socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            { std::cerr << "cannot create socket\n"; exit(1); }
        int one = 1;
        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0) 
            { perror("setsockopt failed"); exit(1); }
        return sock;
    }
    

    // This structure holds all the callbacks for the endpoint. These are function objects
    // that are called asynchronously.

    struct tcp_callbacks {
        thunk__net__tcp__impl__handle_accept acb;
        thunk__net__tcp__impl__handle_recv rcb;
        thunk__net__tcp__impl__handle_fail fcb;
        thunk__net__tcp__impl__handle_connected ccb;
        tcp_callbacks(const thunk__net__tcp__impl__handle_accept &acb,
                      const thunk__net__tcp__impl__handle_recv &rcb,
                      const thunk__net__tcp__impl__handle_fail &fcb,
                      const thunk__net__tcp__impl__handle_connected ccb)
            : acb(acb), rcb(rcb), fcb(fcb), ccb(ccb) {}
    };

    // This is a general class for an asynchronous task. These objects are called in a loop
    // by a thread allocated by the runtime. The fdes method returns a file descriptor
    // associated with the object. If fdes returns a negative value, the thread deletes the
    // object and terminates.

    class tcp_task : public reader {
      protected:
        int sock;           // socket associated to this task, or -1 if task complete
        int my_id;          // endpoint id associated to this task
        tcp_callbacks cb;   // callbacks to ivy
        ivy_class *ivy;     // pointer to main ivy object (mainly to get lock)

      public:

        tcp_task(int my_id, int sock, const tcp_callbacks &cb, ivy_class *ivy)
          : my_id(my_id), sock(sock), cb(cb), ivy(ivy) {} 

        virtual int fdes() {
            return sock;
        }


    };


    // This task reads messages from a socket and calls the "recv" callback.

    class tcp_reader : public tcp_task {
        std::vector<char> buf;
      public:
        tcp_reader(int my_id, int sock, const tcp_callbacks &cb, ivy_class *ivy)
            : tcp_task(my_id, sock, cb, ivy) {
        }

        // This is called in a loop by the task thread.

        virtual void read() {
//            std::cout << "RECEIVING\n";

            craq_system::msg pkt;                      // holds received message
            ivy_socket_deser ds(sock,buf);  // initializer deserialize with any leftover bytes
            buf.clear();                    // clear the leftover bytes

            try {
                __deser(ds,pkt);            // read the message
            } 

            // If packet has bad syntax, we drop it, close the socket, call the "failed"
            // callback and terminate the task.

            catch (deser_err &){
                if (ds.pos > 0)
                    std::cout << "BAD PACKET RECEIVED\n";
                else
                    std::cout << "EOF ON SOCKET\n";
                cb.fcb(sock);
                close(sock);
                sock = -1;
                return;
            }

            // copy the leftover bytes to buf

            buf.resize(ds.inp.size()-ds.pos);
            std::copy(ds.inp.begin()+ds.pos,ds.inp.end(),buf.begin());

            // call the "recv" callback with the received message

            ivy->__lock();
            cb.rcb(sock,pkt);
            ivy->__unlock();
        }
    };


    // This class writes queued packets to a socket. Packets can be added
    // asynchronously to the tail of the queue. If the socket is closed,
    // the queue will be emptied asynchrnonously. When the queue is empty the writer deletes
    // the queue and exits.

    // invariant: if socket is closed, queue is closed

    class tcp_writer : public tcp_task {
        tcp_queue *queue;
        bool connected;
      public:
        tcp_writer(int my_id, int sock, tcp_queue *queue, const tcp_callbacks &cb, ivy_class *ivy)
            : tcp_task(my_id,sock,cb,ivy), queue(queue), connected(false) {
        }

        virtual int fdes() {
            return sock;
        }

        // This is called in a loop by the task thread.

        virtual void read() {

            if (!connected) {
            
                // if the socket is not connected, wait for the queue to be open,
                // then connect

                queue->wait_open();
                connect();
                return;
            }

            // dequeue a packet to send

            std::vector<char> buf;
            bool qclosed = queue->dequeue_swap(buf);        

            // if queue has been closed asynchrononously, close the socket. 

            if (qclosed) {
                // std::cout << "CLOSING " << sock << std::endl;
                ::close(sock);
                connected = false;
                return;
            }

            // try a blocking send

            int bytes = send(sock,&buf[0],buf.size(),MSG_NOSIGNAL);
        
            // std::cout << "SENT\n";

            // if not all bytes sent, channel has failed, close the queue

            if (bytes < (int)buf.size())
                fail_close();
        }

        void connect() {

            // Get the address of the other from the configuration

            // std::cout << "ENTERING CONNECT " << sock << std::endl;

            ivy -> __lock();               // can be asynchronous, so must lock ivy!
            struct sockaddr_in myaddr;
            int other = queue->other;
            get_tcp_addr(ivy,other,myaddr);
            ivy -> __unlock(); 

            // Call connect to make connection

            // std::cout << "CONNECTING sock=" << sock << "other=" << other << std::endl;

            int res = ::connect(sock,(sockaddr *)&myaddr,sizeof(myaddr));

            // If successful, call the "connected" callback, else "failed"
            
            ivy->__lock();
            if (res >= 0) {
                // std::cout << "CONNECT SUCCEEDED " << sock << std::endl;
                cb.ccb(sock);
                connected = true;
            }
            else {
                // std::cout << "CONNECT FAILED " << sock << std::endl;
                fail_close();
            }
            ivy->__unlock();

        }

        void fail_close() {
            queue -> set_closed(false);  // close queue synchronously

            // make sure socket is closed before fail callback, since this
            // might open another socket, and we don't want to build up
            // zombie sockets.

            // std::cout << "CLOSING ON FAILURE " << sock << std::endl;
            ::close(sock);
            cb.fcb(sock);
            connected = false;
        }

    };

    // This task listens for connections on a socket in the background. 

    class tcp_listener : public tcp_task {
      public:

        // The constructor creates a socket to listen on.

        tcp_listener(int my_id, const tcp_callbacks &cb, ivy_class *ivy)
            : tcp_task(my_id,0,cb,ivy) {
            sock = make_tcp_socket();
        }

        // The bind method is called by the runtime once, after initialization.
        // This allows us to query the configuration for our address and bind the socket.

        virtual void bind() {
            ivy -> __lock();  // can be asynchronous, so must lock ivy!

            // Get our endpoint address from the configuration
            struct sockaddr_in myaddr;
            get_tcp_addr(ivy,my_id,myaddr);

                    std::cout << "binding id: " << my_id << " port: " << ntohs(myaddr.sin_port) << std::endl;

            // Bind the socket to our address
            if (::bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0)
                { perror("bind failed"); exit(1); }

            // Start lisetning on the socket
            if (listen(sock,2) < 0) 
                { std::cerr << "cannot listen on socket\n"; exit(1); }

            ivy -> __unlock();
        }

        // After binding, the thread calls read in a loop. In this case, we don't read,
        // we try accepting a connection. BUG: We should first call select to wait for a connection
        // to be available, then call accept while holding the ivy lock. This is needed to
        // guarantee the "accepted" appears to occur before "connected" which is required by
        // the the tcp interface specification.

        virtual void read() {
            // std::cout << "ACCEPTING\n";

            // Call accept to get an incoming connection request. May block.
            sockaddr_in other_addr;
            socklen_t addrlen = sizeof(other_addr);    
            int new_sock = accept(sock, (sockaddr *)&other_addr, &addrlen);

            // If this fails, something is very wrong: fail stop.
            if (new_sock < 0)
                { perror("accept failed"); exit(1); }

            // Get the endpoint id of the other from its address.
            int other = get_tcp_id(ivy,other_addr);

            // Run the "accept" callback. Since it's async, we must lock.
            ivy->__lock();
            cb.acb(new_sock,other);
            ivy->__unlock();

            // Install a reader task to read messages from the new socket.
            ivy->install_reader(new tcp_reader(my_id,new_sock,cb,ivy));
        }
    };



	class sec_timer : public timer {
	    thunk__trans__timer__impl__handle_timeout rcb;
            int ttl;
	    ivy_class *ivy;
	  public:
	    sec_timer(thunk__trans__timer__impl__handle_timeout rcb, ivy_class *ivy)
	        : rcb(rcb), ivy(ivy) {
                ttl = 1000;
	    }
	    virtual int ms_delay() {
		return ttl;
	    }
	    virtual void timeout(int elapse) {
                ttl -= elapse;
                if (ttl <= 0) {
                    ttl = 1000;
		    ivy->__lock();
		    rcb();
		    ivy->__unlock();
                }
	    }
	};
    int craq_system::___ivy_choose(int rng,const char *name,int id) {
        return 0;
    }
unsigned craq_system::__num0(){
    unsigned val;
    val = (unsigned)___ivy_choose(0,"ret:val",0);
    val =  0 ;
    return val;
}
unsigned craq_system::node__max(){
    unsigned val;
    val = (unsigned)___ivy_choose(0,"ret:val",0);
    val =  node__size - 1 ;
    return val;
}
void craq_system::__init(){
    {
        bool __tmp0[32];
for (unsigned A = 0; A < 32; A++) {
        __tmp0[A] = false;
}
for (unsigned A = 0; A < 32; A++) {
        net__proc__isup[A] = __tmp0[A];
}
        bool __tmp1[32];
for (unsigned A = 0; A < 32; A++) {
        __tmp1[A] = false;
}
for (unsigned A = 0; A < 32; A++) {
        net__proc__pend[A] = __tmp1[A];
}
    }
    {
        unsigned long long __tmp2[32];
for (unsigned D = 0; D < 32; D++) {
        __tmp2[D] = (0 & 18446744073709551615);
}
for (unsigned D = 0; D < 32; D++) {
        trans__recv_seq[D] = __tmp2[D];
}
        unsigned long long __tmp3[32];
for (unsigned D = 0; D < 32; D++) {
        __tmp3[D] = (0 & 18446744073709551615);
}
for (unsigned D = 0; D < 32; D++) {
        trans__send_seq[D] = __tmp3[D];
}
    }
    {
        hash_thunk<unsigned long long,bool> __tmp4;
for (unsigned long long K = 0; K < 0; K++) {
        __tmp4[K] = false;
}
for (unsigned long long K = 0; K < 0; K++) {
        system__server__dBitMap[K] = __tmp4[K];
}
        hash_thunk<unsigned long long,unsigned long long> __tmp5;
for (unsigned long long K = 0; K < 0; K++) {
        __tmp5[K] = (0 & 18446744073709551615);
}
for (unsigned long long K = 0; K < 0; K++) {
        system__server__highestVersion[K] = __tmp5[K];
}
        struct __thunk__0 : thunk<craq_system::key_tups__t,__strlit>{
            __thunk__0()  {
            }
            __strlit operator()(const craq_system::key_tups__t &arg){
                return "";
            }
        };
        system__server__mvMap = hash_thunk<craq_system::key_tups__t,__strlit>(new __thunk__0());
        hash_thunk<unsigned long long,__strlit> __tmp6;
for (unsigned long long K = 0; K < 0; K++) {
        __tmp6[K] = "";
}
for (unsigned long long K = 0; K < 0; K++) {
        system__server__viewMap[K] = __tmp6[K];
}
    }
}
void craq_system::ext__trans__handle_request(const query& rq){
    {
        if((me == __num0())){
            ext__system__server__set(rq.qkey, rq.qvalue);
        }
        else {
            {
                                key_tups__t loc__key_pair;
    loc__key_pair.x = (unsigned long long)___ivy_choose(0,"loc:key_pair",612);
    loc__key_pair.y = (unsigned long long)___ivy_choose(0,"loc:key_pair",612);
                {
                    loc__key_pair.x = rq.qkey;
                    loc__key_pair.y = rq.qvnum;
                    system__server__mvMap[loc__key_pair] = rq.qvalue;
                    system__server__highestVersion[rq.qkey] = rq.qvnum;
                    if(!(me == node__max())){
                        {
                            system__server__dBitMap[rq.qkey] = true;
                            {
                                                                unsigned loc__0;
    loc__0 = (unsigned)___ivy_choose(0,"loc:0",611);
                                {
                                    loc__0 = ext__node__next(me);
                                    ext__trans__send_request(loc__0, rq);
                                }
                            }
                        }
                    }
                    else {
                        {
                            system__server__viewMap[rq.qkey] = rq.qvalue;
                            ext__spec__commit(rq, rq);
                            ext__trans__send_reply(me, rq);
                            ext__trans__send_commitAck(me, rq);
                        }
                    }
                }
            }
        }
    }
}
void craq_system::ext__system__server__get(unsigned long long k){
    {
        {
                        query loc__q;
    loc__q.qkey = (unsigned long long)___ivy_choose(0,"loc:q",615);
    loc__q.qtype = (query_type)___ivy_choose(0,"loc:q",615);
    loc__q.qsrc = (unsigned)___ivy_choose(0,"loc:q",615);
    loc__q.qid = (unsigned long long)___ivy_choose(0,"loc:q",615);
    loc__q.qvnum = (unsigned long long)___ivy_choose(0,"loc:q",615);
            {
                loc__q.qkey = k;
                loc__q.qtype = read;
                loc__q.qsrc = me;
                loc__q.qid = system__server__req_no;
                system__server__req_no = ext__req_num__next(system__server__req_no);
                if(!system__server__dBitMap[k]){
                    {
                        loc__q.qvnum = system__server__highestVersion[k];
                        {
                                                        query loc__rep;
    loc__rep.qkey = (unsigned long long)___ivy_choose(0,"loc:rep",614);
    loc__rep.qtype = (query_type)___ivy_choose(0,"loc:rep",614);
    loc__rep.qsrc = (unsigned)___ivy_choose(0,"loc:rep",614);
    loc__rep.qid = (unsigned long long)___ivy_choose(0,"loc:rep",614);
    loc__rep.qvnum = (unsigned long long)___ivy_choose(0,"loc:rep",614);
                            {
                                loc__rep = loc__q;
                                {
                                                                        key_tups__t loc__key_pair;
    loc__key_pair.x = (unsigned long long)___ivy_choose(0,"loc:key_pair",613);
    loc__key_pair.y = (unsigned long long)___ivy_choose(0,"loc:key_pair",613);
                                    {
                                        loc__key_pair.x = k;
                                        loc__key_pair.y = system__server__highestVersion[k];
                                        loc__rep.qvalue = system__server__viewMap[k];
                                        ext__spec__commit(loc__q, loc__rep);
                                        ext__trans__send_reply(me, loc__rep);
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    ext__trans__send_inquire(node__max(), loc__q);
                }
            }
        }
    }
}
unsigned long long craq_system::ext__ver_num__next(unsigned long long seq){
    unsigned long long res;
    res = (unsigned long long)___ivy_choose(0,"fml:res",0);
    {
        res = ((seq + (1 & 18446744073709551615)) & 18446744073709551615);
    }
    return res;
}
void craq_system::ext__trans__mq__imap__set(unsigned prm__D, unsigned long long nkey, const msg& v){
    {

        trans__mq__imap__impl__s[prm__D][nkey] = v;
    }
}
void craq_system::ext__trans__handle_commitAck(const query& rq){
    {
        if((!(me == node__max()) && (system__server__highestVersion[rq.qkey] == rq.qvnum))){
            {
                system__server__dBitMap[rq.qkey] = false;
                system__server__viewMap[rq.qkey] = rq.qvalue;
            }
        }
        if(!(me == __num0())){
            {
                                unsigned loc__0;
    loc__0 = (unsigned)___ivy_choose(0,"loc:0",616);
                {
                    loc__0 = ext__node__prev(me);
                    ext__trans__send_commitAck(loc__0, rq);
                }
            }
        }
    }
}
void craq_system::ext__net__tcp__failed(int s){
    {
        {
                        unsigned loc__other;
            int __tmp7;
            __tmp7 = 0;
            for (unsigned X__0 = 0; X__0 < 32; X__0++) {
                if(((net__proc__isup[X__0] || net__proc__pend[X__0]) && (net__proc__sock[X__0] == s))){
                    loc__other = X__0;
                    __tmp7= 1;
                }
            }
            if(__tmp7){
                {
                    net__proc__isup[loc__other] = false;
                    net__proc__pend[loc__other] = false;
                }
            }
        }
    }
}
void craq_system::net__tcp__impl__handle_fail(int s){
    ext__net__tcp__failed(s);
}
unsigned craq_system::ext__node__prev(unsigned x){
    unsigned y;
    y = (unsigned)___ivy_choose(0,"fml:y",0);
    {
        y = x - 1;
    }
    return y;
}
void craq_system::ext__net__recv(const msg& v){
    {
        {
                        unsigned long long loc__seq;
    loc__seq = (unsigned long long)___ivy_choose(0,"loc:seq",619);
            {
                loc__seq = v.msgnum;
                {
                                        unsigned loc__src;
    loc__src = (unsigned)___ivy_choose(0,"loc:src",618);
                    {
                        loc__src = v.src;
                        if((((loc__seq < trans__recv_seq[loc__src]) || (loc__seq == trans__recv_seq[loc__src])) && !(v.t == msg_type__ack))){
                            {
                                                                msg loc__ack;
    loc__ack.t = (msg_type)___ivy_choose(0,"loc:ack",617);
    loc__ack.src = (unsigned)___ivy_choose(0,"loc:ack",617);
    loc__ack.msgnum = (unsigned long long)___ivy_choose(0,"loc:ack",617);
    loc__ack.body.qkey = (unsigned long long)___ivy_choose(0,"loc:ack",617);
    loc__ack.body.qtype = (query_type)___ivy_choose(0,"loc:ack",617);
    loc__ack.body.qsrc = (unsigned)___ivy_choose(0,"loc:ack",617);
    loc__ack.body.qid = (unsigned long long)___ivy_choose(0,"loc:ack",617);
    loc__ack.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:ack",617);
                                {
                                    loc__ack.t = msg_type__ack;
                                    loc__ack.src = me;
                                    loc__ack.msgnum = loc__seq;
                                    ext__net__send(loc__src, loc__ack);
                                }
                            }
                        }
                        if((v.t == msg_type__ack)){
                            ext__trans__mq__delete_all(loc__src, loc__seq);
                        }
                        else {
                            if((loc__seq == trans__recv_seq[loc__src])){
                                {
                                    trans__recv_seq[loc__src] = ext__msg_num__next(trans__recv_seq[loc__src]);
                                    if((v.t == msg_type__request)){
                                        ext__trans__handle_request(v.body);
                                    }
                                    else {
                                        if((v.t == msg_type__reply)){
                                            ext__trans__handle_reply(v.body);
                                        }
                                        else {
                                            if((v.t == msg_type__inquire)){
                                                ext__trans__handle_inquire(v.body);
                                            }
                                            else {
                                                if((v.t == msg_type__inform)){
                                                    ext__trans__handle_inform(v.body);
                                                }
                                                else {
                                                    if((v.t == msg_type__commitAck)){
                                                        ext__trans__handle_commitAck(v.body);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
void craq_system::ext__trans__handle_reply(const query& rq){
    {
        ext__system__server__answer(rq.qkey, rq.qvalue, rq.qid);
    }
}
void craq_system::ext__trans__timer__timeout(unsigned prm__D){
    {
        {
                        bool loc__0;
    loc__0 = (bool)___ivy_choose(0,"loc:0",621);
            {
                loc__0 = ext__trans__mq__empty(prm__D);
                if(!loc__0){
                    {
                                                msg loc__0;
    loc__0.t = (msg_type)___ivy_choose(0,"loc:0",620);
    loc__0.src = (unsigned)___ivy_choose(0,"loc:0",620);
    loc__0.msgnum = (unsigned long long)___ivy_choose(0,"loc:0",620);
    loc__0.body.qkey = (unsigned long long)___ivy_choose(0,"loc:0",620);
    loc__0.body.qtype = (query_type)___ivy_choose(0,"loc:0",620);
    loc__0.body.qsrc = (unsigned)___ivy_choose(0,"loc:0",620);
    loc__0.body.qid = (unsigned long long)___ivy_choose(0,"loc:0",620);
    loc__0.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:0",620);
                        {
                            loc__0 = ext__trans__mq__pick_one(prm__D);
                            ext__net__send(prm__D, loc__0);
                        }
                    }
                }
            }
        }
    }
}
void craq_system::ext__trans__handle_inquire(const query& rq){
    {
        {
                        query loc__rep;
    loc__rep.qkey = (unsigned long long)___ivy_choose(0,"loc:rep",622);
    loc__rep.qtype = (query_type)___ivy_choose(0,"loc:rep",622);
    loc__rep.qsrc = (unsigned)___ivy_choose(0,"loc:rep",622);
    loc__rep.qid = (unsigned long long)___ivy_choose(0,"loc:rep",622);
    loc__rep.qvnum = (unsigned long long)___ivy_choose(0,"loc:rep",622);
            {
                loc__rep.qkey = rq.qkey;
                loc__rep.qtype = rq.qtype;
                loc__rep.qid = rq.qid;
                loc__rep.qsrc = rq.qsrc;
                loc__rep.qvnum = system__server__highestVersion[rq.qkey];
                ext__trans__send_inform(rq.qsrc, loc__rep);
            }
        }
    }
}
unsigned long long craq_system::ext__msg_num__next(unsigned long long seq){
    unsigned long long res;
    res = (unsigned long long)___ivy_choose(0,"fml:res",0);
    {
        res = ((seq + (1 & 18446744073709551615)) & 18446744073709551615);
    }
    return res;
}
bool craq_system::ext__trans__mq__empty(unsigned prm__D){
    bool res;
    res = (bool)___ivy_choose(0,"fml:res",0);
    {
        {
                        msg_num__iter__t loc__0;
    loc__0.is_end = (bool)___ivy_choose(0,"loc:0",623);
    loc__0.val = (unsigned long long)___ivy_choose(0,"loc:0",623);
                        msg_num__iter__t loc__1;
    loc__1.is_end = (bool)___ivy_choose(0,"loc:1",623);
    loc__1.val = (unsigned long long)___ivy_choose(0,"loc:1",623);
            {
                loc__0 = ext__msg_num__iter__create((0 & 18446744073709551615));
                loc__1 = ext__trans__mq__imap__lub(prm__D, loc__0);
                res = loc__1.is_end;
            }
        }
    }
    return res;
}
void craq_system::ext__trans__send_inquire(unsigned dst, const query& rq){
    {
        {
                        msg loc__m;
    loc__m.t = (msg_type)___ivy_choose(0,"loc:m",624);
    loc__m.src = (unsigned)___ivy_choose(0,"loc:m",624);
    loc__m.msgnum = (unsigned long long)___ivy_choose(0,"loc:m",624);
    loc__m.body.qkey = (unsigned long long)___ivy_choose(0,"loc:m",624);
    loc__m.body.qtype = (query_type)___ivy_choose(0,"loc:m",624);
    loc__m.body.qsrc = (unsigned)___ivy_choose(0,"loc:m",624);
    loc__m.body.qid = (unsigned long long)___ivy_choose(0,"loc:m",624);
    loc__m.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:m",624);
            {
                loc__m.t = msg_type__inquire;
                loc__m.src = me;
                loc__m.msgnum = trans__send_seq[dst];
                loc__m.body = rq;
                trans__send_seq[dst] = ext__msg_num__next(trans__send_seq[dst]);
                ext__trans__mq__enqueue(dst, loc__m);
                ext__net__send(dst, loc__m);
            }
        }
    }
}
void craq_system::ext__trans__send_commitAck(unsigned dst, const query& rq){
    {
        {
                        msg loc__m;
    loc__m.t = (msg_type)___ivy_choose(0,"loc:m",625);
    loc__m.src = (unsigned)___ivy_choose(0,"loc:m",625);
    loc__m.msgnum = (unsigned long long)___ivy_choose(0,"loc:m",625);
    loc__m.body.qkey = (unsigned long long)___ivy_choose(0,"loc:m",625);
    loc__m.body.qtype = (query_type)___ivy_choose(0,"loc:m",625);
    loc__m.body.qsrc = (unsigned)___ivy_choose(0,"loc:m",625);
    loc__m.body.qid = (unsigned long long)___ivy_choose(0,"loc:m",625);
    loc__m.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:m",625);
            {
                loc__m.t = msg_type__commitAck;
                loc__m.src = me;
                loc__m.msgnum = trans__send_seq[dst];
                loc__m.body = rq;
                trans__send_seq[dst] = ext__msg_num__next(trans__send_seq[dst]);
                ext__trans__mq__enqueue(dst, loc__m);
                ext__net__send(dst, loc__m);
            }
        }
    }
}
void craq_system::ext__trans__mq__delete_all(unsigned prm__D, unsigned long long seq){
    {
        {
                        msg_num__iter__t loc__0;
    loc__0.is_end = (bool)___ivy_choose(0,"loc:0",626);
    loc__0.val = (unsigned long long)___ivy_choose(0,"loc:0",626);
                        unsigned long long loc__1;
    loc__1 = (unsigned long long)___ivy_choose(0,"loc:1",626);
                        msg_num__iter__t loc__2;
    loc__2.is_end = (bool)___ivy_choose(0,"loc:2",626);
    loc__2.val = (unsigned long long)___ivy_choose(0,"loc:2",626);
            {
                loc__0 = ext__msg_num__iter__create((0 & 18446744073709551615));
                loc__1 = ext__msg_num__next(seq);
                loc__2 = ext__msg_num__iter__create(loc__1);
                ext__trans__mq__imap__erase(prm__D, loc__0, loc__2);
            }
        }
    }
}
bool craq_system::ext__net__tcp__send(int s, const msg& p){
    bool ok;
    ok = (bool)___ivy_choose(0,"fml:ok",0);
    {
                        ivy_binary_ser sr;
                        __ser(sr,p);
        //                std::cout << "SENDING\n";
        
                        // if the send queue for this sock doesn's exist, it isn't open,
                        // so the client has vioalted the precondition. we do the bad client
                        // the service of not crashing.
        
                        if (net__tcp__impl__send_queue.find(s) == net__tcp__impl__send_queue.end())
                            ok = true;
        
                        else {
                            // get the send queue, and enqueue the packet, returning false if
                            // the queue is closed.
        
                            ok = !net__tcp__impl__send_queue[s]->enqueue_swap(sr.res);
                       }
    }
    return ok;
}
unsigned long long craq_system::ext__req_num__next(unsigned long long seq){
    unsigned long long res;
    res = (unsigned long long)___ivy_choose(0,"fml:res",0);
    {
        res = ((seq + (1 & 18446744073709551615)) & 18446744073709551615);
    }
    return res;
}
void craq_system::trans__timer__impl__handle_timeout(unsigned prm__D){
    ext__trans__timer__timeout(prm__D);
}
void craq_system::ext__trans__send_inform(unsigned dst, const query& rq){
    {
        {
                        msg loc__m;
    loc__m.t = (msg_type)___ivy_choose(0,"loc:m",627);
    loc__m.src = (unsigned)___ivy_choose(0,"loc:m",627);
    loc__m.msgnum = (unsigned long long)___ivy_choose(0,"loc:m",627);
    loc__m.body.qkey = (unsigned long long)___ivy_choose(0,"loc:m",627);
    loc__m.body.qtype = (query_type)___ivy_choose(0,"loc:m",627);
    loc__m.body.qsrc = (unsigned)___ivy_choose(0,"loc:m",627);
    loc__m.body.qid = (unsigned long long)___ivy_choose(0,"loc:m",627);
    loc__m.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:m",627);
            {
                loc__m.t = msg_type__inform;
                loc__m.src = me;
                loc__m.msgnum = trans__send_seq[dst];
                loc__m.body = rq;
                trans__send_seq[dst] = ext__msg_num__next(trans__send_seq[dst]);
                ext__trans__mq__enqueue(dst, loc__m);
                ext__net__send(dst, loc__m);
            }
        }
    }
}
void craq_system::ext__trans__mq__imap__erase(unsigned prm__D, const msg_num__iter__t& lo, const msg_num__iter__t& hi){
    {



        if (!lo.is_end && (hi.is_end || lo.val < hi.val))
          trans__mq__imap__impl__s[prm__D].erase(lo.is_end ? trans__mq__imap__impl__s[prm__D].end() : trans__mq__imap__impl__s[prm__D].lower_bound(lo.val),
                    hi.is_end ? trans__mq__imap__impl__s[prm__D].end() : trans__mq__imap__impl__s[prm__D].lower_bound(hi.val));
    }
}
int craq_system::ext__net__tcp__connect(unsigned other){
    int s;
    s = (int)___ivy_choose(0,"fml:s",0);
    {
        s = make_tcp_socket();
        // std::cout << "SOCKET " << s << std::endl;

        // create a send queue for this socket, if needed, along with
        // its thread. if the queue exists, it must be closed, so
        // we open it.

        tcp_queue *queue;
        if (net__tcp__impl__send_queue.find(s) == net__tcp__impl__send_queue.end()) {
            net__tcp__impl__send_queue[s] = queue = new tcp_queue(other);
             install_thread(new tcp_writer(me,s,queue,*net__tcp__impl__cb,this));
        } else
            net__tcp__impl__send_queue[s] -> set_open(other);
    }
    return s;
}
void craq_system::ext__net__tcp__accept(int s, unsigned other){
    {
    }
}
void craq_system::ext__net__tcp__recv(int s, const msg& p){
    {
        ext__net__recv(p);
    }
}
craq_system::msg craq_system::ext__trans__mq__pick_one(unsigned prm__D){
    craq_system::msg res;
    res.t = (msg_type)___ivy_choose(0,"fml:res",0);
    res.src = (unsigned)___ivy_choose(0,"fml:res",0);
    res.msgnum = (unsigned long long)___ivy_choose(0,"fml:res",0);
    res.body.qkey = (unsigned long long)___ivy_choose(0,"fml:res",0);
    res.body.qtype = (query_type)___ivy_choose(0,"fml:res",0);
    res.body.qsrc = (unsigned)___ivy_choose(0,"fml:res",0);
    res.body.qid = (unsigned long long)___ivy_choose(0,"fml:res",0);
    res.body.qvnum = (unsigned long long)___ivy_choose(0,"fml:res",0);
    {
        {
                        msg_num__iter__t loc__0;
    loc__0.is_end = (bool)___ivy_choose(0,"loc:0",631);
    loc__0.val = (unsigned long long)___ivy_choose(0,"loc:0",631);
                        msg_num__iter__t loc__1;
    loc__1.is_end = (bool)___ivy_choose(0,"loc:1",631);
    loc__1.val = (unsigned long long)___ivy_choose(0,"loc:1",631);
            {
                loc__0 = ext__msg_num__iter__create((0 & 18446744073709551615));
                loc__1 = ext__trans__mq__imap__lub(prm__D, loc__0);
                res = ext__trans__mq__imap__get(prm__D, loc__1.val, res);
            }
        }
    }
    return res;
}
void craq_system::ext__system__server__set(unsigned long long k, __strlit d){
    {
        {
                        query loc__q;
    loc__q.qkey = (unsigned long long)___ivy_choose(0,"loc:q",630);
    loc__q.qtype = (query_type)___ivy_choose(0,"loc:q",630);
    loc__q.qsrc = (unsigned)___ivy_choose(0,"loc:q",630);
    loc__q.qid = (unsigned long long)___ivy_choose(0,"loc:q",630);
    loc__q.qvnum = (unsigned long long)___ivy_choose(0,"loc:q",630);
            {
                loc__q.qkey = k;
                loc__q.qtype = write;
                loc__q.qvalue = d;
                loc__q.qsrc = me;
                loc__q.qid = system__server__req_no;
                system__server__req_no = ext__req_num__next(system__server__req_no);
                if((me == __num0())){
                    {
                        system__server__ver_no = ext__ver_num__next(system__server__ver_no);
                        loc__q.qvnum = system__server__ver_no;
                        {
                                                        key_tups__t loc__key_pair;
    loc__key_pair.x = (unsigned long long)___ivy_choose(0,"loc:key_pair",629);
    loc__key_pair.y = (unsigned long long)___ivy_choose(0,"loc:key_pair",629);
                            {
                                loc__key_pair.x = k;
                                loc__key_pair.y = system__server__ver_no;
                                system__server__mvMap[loc__key_pair] = d;
                                system__server__highestVersion[k] = system__server__ver_no;
                                if(!(me == node__max())){
                                    {
                                        system__server__dBitMap[k] = true;
                                        {
                                                                                        unsigned loc__0;
    loc__0 = (unsigned)___ivy_choose(0,"loc:0",628);
                                            {
                                                loc__0 = ext__node__next(me);
                                                ext__trans__send_request(loc__0, loc__q);
                                            }
                                        }
                                    }
                                }
                                else {
                                    {
                                        system__server__viewMap[k] = d;
                                        ext__spec__commit(loc__q, loc__q);
                                        ext__trans__send_reply(me, loc__q);
                                        ext__trans__send_commitAck(me, loc__q);
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    ext__trans__send_request(__num0(), loc__q);
                }
            }
        }
    }
}
void craq_system::ext__spec__commit(const query& req, const query& repl){
    {
    }
}
void craq_system::net__tcp__impl__handle_accept(int s, unsigned other){
    ext__net__tcp__accept(s, other);
}
void craq_system::ext__trans__send_reply(unsigned dst, const query& rq){
    {
        {
                        msg loc__m;
    loc__m.t = (msg_type)___ivy_choose(0,"loc:m",632);
    loc__m.src = (unsigned)___ivy_choose(0,"loc:m",632);
    loc__m.msgnum = (unsigned long long)___ivy_choose(0,"loc:m",632);
    loc__m.body.qkey = (unsigned long long)___ivy_choose(0,"loc:m",632);
    loc__m.body.qtype = (query_type)___ivy_choose(0,"loc:m",632);
    loc__m.body.qsrc = (unsigned)___ivy_choose(0,"loc:m",632);
    loc__m.body.qid = (unsigned long long)___ivy_choose(0,"loc:m",632);
    loc__m.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:m",632);
            {
                loc__m.t = msg_type__reply;
                loc__m.src = me;
                loc__m.msgnum = trans__send_seq[dst];
                loc__m.body = rq;
                trans__send_seq[dst] = ext__msg_num__next(trans__send_seq[dst]);
                ext__trans__mq__enqueue(dst, loc__m);
                ext__net__send(dst, loc__m);
            }
        }
    }
}
void craq_system::imp__system__server__answer(unsigned long long k, __strlit v, unsigned long long id){
    {
    }
}
void craq_system::ext__net__send(unsigned dst, const msg& v){
    {
        if(!net__proc__isup[dst]){
            if(!net__proc__pend[dst]){
                {
                    net__proc__sock[dst] = ext__net__tcp__connect(dst);
                    net__proc__pend[dst] = true;
                }
            }
        }
        else {
            {
                                bool loc__0;
    loc__0 = (bool)___ivy_choose(0,"loc:0",634);
                {
                    loc__0 = ext__net__tcp__send(net__proc__sock[dst], v);
                    {
                                                bool loc__ok;
    loc__ok = (bool)___ivy_choose(0,"loc:ok",633);
                        {
                            loc__ok = loc__0;
                            if(!loc__ok){
                                {
                                    ext__net__tcp__close(net__proc__sock[dst]);
                                    net__proc__sock[dst] = ext__net__tcp__connect(dst);
                                    net__proc__isup[dst] = false;
                                    net__proc__pend[dst] = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
void craq_system::ext__trans__handle_inform(const query& rq){
    {
        ivy_assume((system__server__dBitMap[rq.qkey] == true), "craq_system.ivy: line 138");
        {
                        query loc__rep;
    loc__rep.qkey = (unsigned long long)___ivy_choose(0,"loc:rep",636);
    loc__rep.qtype = (query_type)___ivy_choose(0,"loc:rep",636);
    loc__rep.qsrc = (unsigned)___ivy_choose(0,"loc:rep",636);
    loc__rep.qid = (unsigned long long)___ivy_choose(0,"loc:rep",636);
    loc__rep.qvnum = (unsigned long long)___ivy_choose(0,"loc:rep",636);
            {
                loc__rep.qkey = rq.qkey;
                loc__rep.qtype = rq.qtype;
                loc__rep.qsrc = rq.qsrc;
                loc__rep.qid = rq.qid;
                loc__rep.qvnum = rq.qvnum;
                if((system__server__highestVersion[rq.qkey] == rq.qvnum)){
                    system__server__dBitMap[rq.qkey] = false;
                }
                {
                                        key_tups__t loc__key_pair;
    loc__key_pair.x = (unsigned long long)___ivy_choose(0,"loc:key_pair",635);
    loc__key_pair.y = (unsigned long long)___ivy_choose(0,"loc:key_pair",635);
                    {
                        loc__key_pair.x = rq.qkey;
                        loc__key_pair.y = rq.qvnum;
                        system__server__viewMap[rq.qkey] = system__server__mvMap[loc__key_pair];
                        loc__rep.qvalue = system__server__viewMap[rq.qkey];
                        ext__spec__commit(loc__rep, loc__rep);
                        ext__trans__send_reply(me, loc__rep);
                    }
                }
            }
        }
    }
}
unsigned craq_system::ext__node__next(unsigned x){
    unsigned y;
    y = (unsigned)___ivy_choose(0,"fml:y",0);
    {
        y = x + 1;
    }
    return y;
}
craq_system::msg_num__iter__t craq_system::ext__trans__mq__imap__lub(unsigned prm__D, const msg_num__iter__t& it){
    craq_system::msg_num__iter__t res;
    res.is_end = (bool)___ivy_choose(0,"fml:res",0);
    res.val = (unsigned long long)___ivy_choose(0,"fml:res",0);
    {

        if (it.is_end) {
            res.is_end = true;
            res.val = 0;
        } else {
            std::map<unsigned long long,msg>::iterator __it = trans__mq__imap__impl__s[prm__D].lower_bound(it.val);
            if (__it == trans__mq__imap__impl__s[prm__D].end()) {
                res.is_end = true;
                res.val = 0;
            } else {
                res.is_end = false;
                res.val = __it->first;
            }
        }
    }
    return res;
}
void craq_system::net__tcp__impl__handle_recv(int s, const msg& x){
    ext__net__tcp__recv(s, x);
}
void craq_system::ext__trans__mq__enqueue(unsigned prm__D, msg m){
    {
        ext__trans__mq__imap__set(prm__D, m.msgnum, m);
    }
}
craq_system::msg craq_system::ext__trans__mq__imap__get(unsigned prm__D, unsigned long long k, const msg& def){
    craq_system::msg v;
    v.t = (msg_type)___ivy_choose(0,"fml:v",0);
    v.src = (unsigned)___ivy_choose(0,"fml:v",0);
    v.msgnum = (unsigned long long)___ivy_choose(0,"fml:v",0);
    v.body.qkey = (unsigned long long)___ivy_choose(0,"fml:v",0);
    v.body.qtype = (query_type)___ivy_choose(0,"fml:v",0);
    v.body.qsrc = (unsigned)___ivy_choose(0,"fml:v",0);
    v.body.qid = (unsigned long long)___ivy_choose(0,"fml:v",0);
    v.body.qvnum = (unsigned long long)___ivy_choose(0,"fml:v",0);
    {

        std::map<unsigned long long,msg>::iterator it = trans__mq__imap__impl__s[prm__D].find(k);
        if (it == trans__mq__imap__impl__s[prm__D].end()) {
            v = def;
        } else {
            v = it->second;
        }
    }
    return v;
}
void craq_system::ext__trans__send_request(unsigned dst, const query& rq){
    {
        {
                        msg loc__m;
    loc__m.t = (msg_type)___ivy_choose(0,"loc:m",637);
    loc__m.src = (unsigned)___ivy_choose(0,"loc:m",637);
    loc__m.msgnum = (unsigned long long)___ivy_choose(0,"loc:m",637);
    loc__m.body.qkey = (unsigned long long)___ivy_choose(0,"loc:m",637);
    loc__m.body.qtype = (query_type)___ivy_choose(0,"loc:m",637);
    loc__m.body.qsrc = (unsigned)___ivy_choose(0,"loc:m",637);
    loc__m.body.qid = (unsigned long long)___ivy_choose(0,"loc:m",637);
    loc__m.body.qvnum = (unsigned long long)___ivy_choose(0,"loc:m",637);
            {
                loc__m.t = msg_type__request;
                loc__m.src = me;
                loc__m.msgnum = trans__send_seq[dst];
                loc__m.body = rq;
                trans__send_seq[dst] = ext__msg_num__next(trans__send_seq[dst]);
                ext__trans__mq__enqueue(dst, loc__m);
                ext__net__send(dst, loc__m);
            }
        }
    }
}
craq_system::msg_num__iter__t craq_system::ext__msg_num__iter__create(unsigned long long x){
    craq_system::msg_num__iter__t y;
    y.is_end = (bool)___ivy_choose(0,"fml:y",0);
    y.val = (unsigned long long)___ivy_choose(0,"fml:y",0);
    {
        y.is_end = false;
        y.val = x;
    }
    return y;
}
void craq_system::ext__system__server__answer(unsigned long long k, __strlit v, unsigned long long id){
    imp__system__server__answer(k, v, id);
}
void craq_system::ext__net__tcp__close(int s){
    {
        
        // We don't want to close a socket when there is another thread
        // waiting, because the other thread won't know what to do with the
        // error.
    
        // Instead we shut down the socket and let the other thread close it.
        // If there is a reader thread, it will see EOF and close the socket. If there is
        // on open writer thread, it will close the socket after we close the
        // send queue. If the queue is already closed, closing it has no effect.

        // invariant: if a socket is open there is a reader thread or
        // an open writer thread, but not both.

        // Because of this invariant, the socket will be closed exactly once.

        ::shutdown(s,SHUT_RDWR);

        if (net__tcp__impl__send_queue.find(s) != net__tcp__impl__send_queue.end())
            net__tcp__impl__send_queue[s] -> set_closed();
    }
}
void craq_system::net__tcp__impl__handle_connected(int s){
    ext__net__tcp__connected(s);
}
void craq_system::ext__net__tcp__connected(int s){
    {
        {
                        unsigned loc__other;
            int __tmp8;
            __tmp8 = 0;
            for (unsigned X__0 = 0; X__0 < 32; X__0++) {
                if((net__proc__pend[X__0] && (net__proc__sock[X__0] == s))){
                    loc__other = X__0;
                    __tmp8= 1;
                }
            }
            if(__tmp8){
                {
                    net__proc__pend[loc__other] = false;
                    net__proc__isup[loc__other] = true;
                }
            }
        }
    }
}
void craq_system::__tick(int __timeout){
}
craq_system::craq_system(unsigned node__size, unsigned me){
#ifdef _WIN32
mutex = CreateMutex(NULL,FALSE,NULL);
#else
pthread_mutex_init(&mutex,NULL);
#endif
__lock();
    __CARD__node = 32;
    __CARD__ver_num__t = 0;
    __CARD__key = 0;
    __CARD__net__tcp__socket = 0;
    __CARD__msg_num__t = 0;
    __CARD__req_num__t = 0;
    __CARD__value = 0;

    the_tcp_config = 0;

    // Create the callbacks. In a parameterized instance, this creates
    // one set of callbacks for each endpoint id. When you put an
    // action in anti-quotes it creates a function object (a "thunk")
    // that captures the instance environment, in this case including
    // the instance's endpoint id "me".

    net__tcp__impl__cb = new tcp_callbacks(thunk__net__tcp__impl__handle_accept(this),thunk__net__tcp__impl__handle_recv(this),thunk__net__tcp__impl__handle_fail(this),thunk__net__tcp__impl__handle_connected(this));

    // Install a listener task for this endpoint. If parameterized, this creates
    // one for each endpoint.

    install_reader(net__tcp__impl__rdr = new tcp_listener(me,*net__tcp__impl__cb,this));
    for (unsigned D = 0; D < 32; D++) {
        
    }
    for (unsigned D = 0; D < 32; D++) {
        install_timer(trans__timer__impl__tmr[D] = new sec_timer(thunk__trans__timer__impl__handle_timeout(this, D),this));
    }
this->node__size = node__size;
struct __thunk__1 : thunk<unsigned long long,bool>{
    __thunk__1()  {
    }
    bool operator()(const unsigned long long &arg){
        bool __tmp9;
    __tmp9 = (bool)___ivy_choose(0,"init",0);
        return __tmp9;
    }
};
system__server__dBitMap = hash_thunk<unsigned long long,bool>(new __thunk__1());
    system__server__req_no = (unsigned long long)___ivy_choose(0,"init",0);
    system__server__ver_no = (unsigned long long)___ivy_choose(0,"init",0);
struct __thunk__2 : thunk<unsigned long long,unsigned long long>{
    __thunk__2()  {
    }
    unsigned long long operator()(const unsigned long long &arg){
        unsigned long long __tmp10;
    __tmp10 = (unsigned long long)___ivy_choose(0,"init",0);
        return __tmp10;
    }
};
system__server__highestVersion = hash_thunk<unsigned long long,unsigned long long>(new __thunk__2());
for (unsigned X__0 = 0; X__0 < 32; X__0++) {
    net__proc__isup[X__0] = (bool)___ivy_choose(0,"init",0);
}
this->me = me;
    _generating = (bool)___ivy_choose(0,"init",0);
for (unsigned X__0 = 0; X__0 < 32; X__0++) {
    net__proc__pend[X__0] = (bool)___ivy_choose(0,"init",0);
}
for (unsigned X__0 = 0; X__0 < 32; X__0++) {
    trans__recv_seq[X__0] = (unsigned long long)___ivy_choose(0,"init",0);
}
for (unsigned X__0 = 0; X__0 < 32; X__0++) {
    trans__send_seq[X__0] = (unsigned long long)___ivy_choose(0,"init",0);
}
for (unsigned X__0 = 0; X__0 < 32; X__0++) {
    net__proc__sock[X__0] = (int)___ivy_choose(0,"init",0);
}
}
craq_system::~craq_system(){
    __lock(); // otherwise, thread may die holding lock!
    for (unsigned i = 0; i < thread_ids.size(); i++){
#ifdef _WIN32
       // No idea how to cancel a thread on Windows. We just suspend it
       // so it can't cause any harm as we destruct this object.
       SuspendThread(thread_ids[i]);
#else
        pthread_cancel(thread_ids[i]);
        pthread_join(thread_ids[i],NULL);
#endif
    }
    __unlock();
}
std::ostream &operator <<(std::ostream &s, const craq_system::msg_num__iter__t &t){
    s<<"{";
    s<< "is_end:";
    s << t.is_end;
    s<<",";
    s<< "val:";
    s << t.val;
    s<<"}";
    return s;
}
template <>
void  __ser<craq_system::msg_num__iter__t>(ivy_ser &res, const craq_system::msg_num__iter__t&t){
    res.open_struct();
    res.open_field("is_end");
    __ser<bool>(res,t.is_end);
    res.close_field();
    res.open_field("val");
    __ser<unsigned long long>(res,t.val);
    res.close_field();
    res.close_struct();
}
std::ostream &operator <<(std::ostream &s, const craq_system::key_tups__t &t){
    s<<"{";
    s<< "x:";
    s << t.x;
    s<<",";
    s<< "y:";
    s << t.y;
    s<<"}";
    return s;
}
template <>
void  __ser<craq_system::key_tups__t>(ivy_ser &res, const craq_system::key_tups__t&t){
    res.open_struct();
    res.open_field("x");
    __ser<unsigned long long>(res,t.x);
    res.close_field();
    res.open_field("y");
    __ser<unsigned long long>(res,t.y);
    res.close_field();
    res.close_struct();
}
std::ostream &operator <<(std::ostream &s, const craq_system::query &t){
    s<<"{";
    s<< "qkey:";
    s << t.qkey;
    s<<",";
    s<< "qtype:";
    s << t.qtype;
    s<<",";
    s<< "qvalue:";
    s << t.qvalue;
    s<<",";
    s<< "qsrc:";
    s << t.qsrc;
    s<<",";
    s<< "qid:";
    s << t.qid;
    s<<",";
    s<< "qvnum:";
    s << t.qvnum;
    s<<"}";
    return s;
}
template <>
void  __ser<craq_system::query>(ivy_ser &res, const craq_system::query&t){
    res.open_struct();
    res.open_field("qkey");
    __ser<unsigned long long>(res,t.qkey);
    res.close_field();
    res.open_field("qtype");
    __ser<craq_system::query_type>(res,t.qtype);
    res.close_field();
    res.open_field("qvalue");
    __ser<__strlit>(res,t.qvalue);
    res.close_field();
    res.open_field("qsrc");
    __ser<unsigned>(res,t.qsrc);
    res.close_field();
    res.open_field("qid");
    __ser<unsigned long long>(res,t.qid);
    res.close_field();
    res.open_field("qvnum");
    __ser<unsigned long long>(res,t.qvnum);
    res.close_field();
    res.close_struct();
}
std::ostream &operator <<(std::ostream &s, const craq_system::msg &t){
    s<<"{";
    s<< "t:";
    s << t.t;
    s<<",";
    s<< "src:";
    s << t.src;
    s<<",";
    s<< "msgnum:";
    s << t.msgnum;
    s<<",";
    s<< "body:";
    s << t.body;
    s<<"}";
    return s;
}
template <>
void  __ser<craq_system::msg>(ivy_ser &res, const craq_system::msg&t){
    res.open_struct();
    res.open_field("t");
    __ser<craq_system::msg_type>(res,t.t);
    res.close_field();
    res.open_field("src");
    __ser<unsigned>(res,t.src);
    res.close_field();
    res.open_field("msgnum");
    __ser<unsigned long long>(res,t.msgnum);
    res.close_field();
    res.open_field("body");
    __ser<craq_system::query>(res,t.body);
    res.close_field();
    res.close_struct();
}
std::ostream &operator <<(std::ostream &s, const craq_system::msg_type &t){
    if (t == craq_system::msg_type__request) s<<"request";
    if (t == craq_system::msg_type__reply) s<<"reply";
    if (t == craq_system::msg_type__inquire) s<<"inquire";
    if (t == craq_system::msg_type__inform) s<<"inform";
    if (t == craq_system::msg_type__commitAck) s<<"commitAck";
    if (t == craq_system::msg_type__ack) s<<"ack";
    return s;
}
template <>
void  __ser<craq_system::msg_type>(ivy_ser &res, const craq_system::msg_type&t){
    __ser(res,(int)t);
}
std::ostream &operator <<(std::ostream &s, const craq_system::query_type &t){
    if (t == craq_system::read) s<<"read";
    if (t == craq_system::write) s<<"write";
    return s;
}
template <>
void  __ser<craq_system::query_type>(ivy_ser &res, const craq_system::query_type&t){
    __ser(res,(int)t);
}


int ask_ret(long long bound) {
    int res;
    while(true) {
        __ivy_out << "? ";
        std::cin >> res;
        if (res >= 0 && res < bound) 
            return res;
        std::cerr << "value out of range" << std::endl;
    }
}



    class craq_system_repl : public craq_system {

    public:

    virtual void ivy_assert(bool truth,const char *msg){
        if (!truth) {
            __ivy_out << "assertion_failed(\"" << msg << "\")" << std::endl;
            std::cerr << msg << ": error: assertion failed\n";
            
            __ivy_exit(1);
        }
    }
    virtual void ivy_assume(bool truth,const char *msg){
        if (!truth) {
            __ivy_out << "assumption_failed(\"" << msg << "\")" << std::endl;
            std::cerr << msg << ": error: assumption failed\n";
            
            __ivy_exit(1);
        }
    }
    craq_system_repl(unsigned node__size, unsigned me) : craq_system(node__size,me){}
    virtual void imp__system__server__answer(unsigned long long k, __strlit v, unsigned long long id){
    __ivy_out  << "< system.server.answer" << "(" << k << "," << v << "," << id << ")" << std::endl;
}

    };

// Override methods to implement low-level network service

bool is_white(int c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

bool is_ident(int c) {
    return c == '_' || c == '.' || (c >= 'A' &&  c <= 'Z')
        || (c >= 'a' &&  c <= 'z')
        || (c >= '0' &&  c <= '9');
}

void skip_white(const std::string& str, int &pos){
    while (pos < str.size() && is_white(str[pos]))
        pos++;
}

struct syntax_error {
    int pos;
    syntax_error(int pos) : pos(pos) {}
};

void throw_syntax(int pos){
    throw syntax_error(pos);
}

std::string get_ident(const std::string& str, int &pos) {
    std::string res = "";
    while (pos < str.size() && is_ident(str[pos])) {
        res.push_back(str[pos]);
        pos++;
    }
    if (res.size() == 0)
        throw_syntax(pos);
    return res;
}

ivy_value parse_value(const std::string& cmd, int &pos) {
    ivy_value res;
    res.pos = pos;
    skip_white(cmd,pos);
    if (pos < cmd.size() && cmd[pos] == '[') {
        while (true) {
            pos++;
            skip_white(cmd,pos);
            if (pos < cmd.size() && cmd[pos] == ']')
                break;
            res.fields.push_back(parse_value(cmd,pos));
            skip_white(cmd,pos);
            if (pos < cmd.size() && cmd[pos] == ']')
                break;
            if (!(pos < cmd.size() && cmd[pos] == ','))
                throw_syntax(pos);
        }
        pos++;
    }
    else if (pos < cmd.size() && cmd[pos] == '{') {
        while (true) {
            ivy_value field;
            pos++;
            skip_white(cmd,pos);
            field.atom = get_ident(cmd,pos);
            skip_white(cmd,pos);
            if (!(pos < cmd.size() && cmd[pos] == ':'))
                 throw_syntax(pos);
            pos++;
            skip_white(cmd,pos);
            field.fields.push_back(parse_value(cmd,pos));
            res.fields.push_back(field);
            skip_white(cmd,pos);
            if (pos < cmd.size() && cmd[pos] == '}')
                break;
            if (!(pos < cmd.size() && cmd[pos] == ','))
                throw_syntax(pos);
        }
        pos++;
    }
    else if (pos < cmd.size() && cmd[pos] == '"') {
        pos++;
        res.atom = "";
        while (pos < cmd.size() && cmd[pos] != '"') {
            char c = cmd[pos++];
            if (c == '\\') {
                if (pos == cmd.size())
                    throw_syntax(pos);
                c = cmd[pos++];
                c = (c == 'n') ? 10 : (c == 'r') ? 13 : (c == 't') ? 9 : c;
            }
            res.atom.push_back(c);
        }
        if(pos == cmd.size())
            throw_syntax(pos);
        pos++;
    }
    else 
        res.atom = get_ident(cmd,pos);
    return res;
}

void parse_command(const std::string &cmd, std::string &action, std::vector<ivy_value> &args) {
    int pos = 0;
    skip_white(cmd,pos);
    action = get_ident(cmd,pos);
    skip_white(cmd,pos);
    if (pos < cmd.size() && cmd[pos] == '(') {
        pos++;
        skip_white(cmd,pos);
        args.push_back(parse_value(cmd,pos));
        while(true) {
            skip_white(cmd,pos);
            if (!(pos < cmd.size() && cmd[pos] == ','))
                break;
            pos++;
            args.push_back(parse_value(cmd,pos));
        }
        if (!(pos < cmd.size() && cmd[pos] == ')'))
            throw_syntax(pos);
        pos++;
    }
    skip_white(cmd,pos);
    if (pos != cmd.size())
        throw_syntax(pos);
}

struct bad_arity {
    std::string action;
    int num;
    bad_arity(std::string &_action, unsigned _num) : action(_action), num(_num) {}
};

void check_arity(std::vector<ivy_value> &args, unsigned num, std::string &action) {
    if (args.size() != num)
        throw bad_arity(action,num);
}

template <>
craq_system::key_tups__t _arg<craq_system::key_tups__t>(std::vector<ivy_value> &args, unsigned idx, long long bound){
    craq_system::key_tups__t res;
    res.x = (unsigned long long)0;
    res.y = (unsigned long long)0;
    ivy_value &arg = args[idx];
    std::vector<ivy_value> tmp_args(1);
    for (unsigned i = 0; i < arg.fields.size(); i++){
        if (arg.fields[i].is_member()){
            tmp_args[0] = arg.fields[i].fields[0];
            if (arg.fields[i].atom == "x"){
                try{
                    res.x = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field x: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "y"){
                try{
                    res.y = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field y: " + err.txt,err.pos);
                }
            }
            else  throw out_of_bounds("unexpected field: " + arg.fields[i].atom,arg.fields[i].pos);
        }
        else throw out_of_bounds("expected struct",args[idx].pos);
    }
    return res;
}
template <>
void __deser<craq_system::key_tups__t>(ivy_deser &inp, craq_system::key_tups__t &res){
    inp.open_struct();
    inp.open_field("x");
    __deser(inp,res.x);
    inp.close_field();
    inp.open_field("y");
    __deser(inp,res.y);
    inp.close_field();
    inp.close_struct();
}
template <>
craq_system::msg _arg<craq_system::msg>(std::vector<ivy_value> &args, unsigned idx, long long bound){
    craq_system::msg res;
    res.t = (craq_system::msg_type)0;
    res.src = (unsigned)0;
    res.msgnum = (unsigned long long)0;
    res.body.qkey = (unsigned long long)0;
    res.body.qtype = (craq_system::query_type)0;
    res.body.qsrc = (unsigned)0;
    res.body.qid = (unsigned long long)0;
    res.body.qvnum = (unsigned long long)0;
    ivy_value &arg = args[idx];
    std::vector<ivy_value> tmp_args(1);
    for (unsigned i = 0; i < arg.fields.size(); i++){
        if (arg.fields[i].is_member()){
            tmp_args[0] = arg.fields[i].fields[0];
            if (arg.fields[i].atom == "t"){
                try{
                    res.t = _arg<craq_system::msg_type>(tmp_args,0,6);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field t: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "src"){
                try{
                    res.src = _arg<unsigned>(tmp_args,0,32);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field src: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "msgnum"){
                try{
                    res.msgnum = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field msgnum: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "body"){
                try{
                    res.body = _arg<craq_system::query>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field body: " + err.txt,err.pos);
                }
            }
            else  throw out_of_bounds("unexpected field: " + arg.fields[i].atom,arg.fields[i].pos);
        }
        else throw out_of_bounds("expected struct",args[idx].pos);
    }
    return res;
}
template <>
void __deser<craq_system::msg>(ivy_deser &inp, craq_system::msg &res){
    inp.open_struct();
    inp.open_field("t");
    __deser(inp,res.t);
    inp.close_field();
    inp.open_field("src");
    __deser(inp,res.src);
    inp.close_field();
    inp.open_field("msgnum");
    __deser(inp,res.msgnum);
    inp.close_field();
    inp.open_field("body");
    __deser(inp,res.body);
    inp.close_field();
    inp.close_struct();
}
template <>
craq_system::msg_num__iter__t _arg<craq_system::msg_num__iter__t>(std::vector<ivy_value> &args, unsigned idx, long long bound){
    craq_system::msg_num__iter__t res;
    res.is_end = (bool)0;
    res.val = (unsigned long long)0;
    ivy_value &arg = args[idx];
    std::vector<ivy_value> tmp_args(1);
    for (unsigned i = 0; i < arg.fields.size(); i++){
        if (arg.fields[i].is_member()){
            tmp_args[0] = arg.fields[i].fields[0];
            if (arg.fields[i].atom == "is_end"){
                try{
                    res.is_end = _arg<bool>(tmp_args,0,2);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field is_end: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "val"){
                try{
                    res.val = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field val: " + err.txt,err.pos);
                }
            }
            else  throw out_of_bounds("unexpected field: " + arg.fields[i].atom,arg.fields[i].pos);
        }
        else throw out_of_bounds("expected struct",args[idx].pos);
    }
    return res;
}
template <>
void __deser<craq_system::msg_num__iter__t>(ivy_deser &inp, craq_system::msg_num__iter__t &res){
    inp.open_struct();
    inp.open_field("is_end");
    __deser(inp,res.is_end);
    inp.close_field();
    inp.open_field("val");
    __deser(inp,res.val);
    inp.close_field();
    inp.close_struct();
}
template <>
craq_system::query _arg<craq_system::query>(std::vector<ivy_value> &args, unsigned idx, long long bound){
    craq_system::query res;
    res.qkey = (unsigned long long)0;
    res.qtype = (craq_system::query_type)0;
    res.qsrc = (unsigned)0;
    res.qid = (unsigned long long)0;
    res.qvnum = (unsigned long long)0;
    ivy_value &arg = args[idx];
    std::vector<ivy_value> tmp_args(1);
    for (unsigned i = 0; i < arg.fields.size(); i++){
        if (arg.fields[i].is_member()){
            tmp_args[0] = arg.fields[i].fields[0];
            if (arg.fields[i].atom == "qkey"){
                try{
                    res.qkey = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field qkey: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "qtype"){
                try{
                    res.qtype = _arg<craq_system::query_type>(tmp_args,0,2);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field qtype: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "qvalue"){
                try{
                    res.qvalue = _arg<__strlit>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field qvalue: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "qsrc"){
                try{
                    res.qsrc = _arg<unsigned>(tmp_args,0,32);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field qsrc: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "qid"){
                try{
                    res.qid = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field qid: " + err.txt,err.pos);
                }
            }
            else if (arg.fields[i].atom == "qvnum"){
                try{
                    res.qvnum = _arg<unsigned long long>(tmp_args,0,0);
                }
                catch(const out_of_bounds &err){
                    throw out_of_bounds("in field qvnum: " + err.txt,err.pos);
                }
            }
            else  throw out_of_bounds("unexpected field: " + arg.fields[i].atom,arg.fields[i].pos);
        }
        else throw out_of_bounds("expected struct",args[idx].pos);
    }
    return res;
}
template <>
void __deser<craq_system::query>(ivy_deser &inp, craq_system::query &res){
    inp.open_struct();
    inp.open_field("qkey");
    __deser(inp,res.qkey);
    inp.close_field();
    inp.open_field("qtype");
    __deser(inp,res.qtype);
    inp.close_field();
    inp.open_field("qvalue");
    __deser(inp,res.qvalue);
    inp.close_field();
    inp.open_field("qsrc");
    __deser(inp,res.qsrc);
    inp.close_field();
    inp.open_field("qid");
    __deser(inp,res.qid);
    inp.close_field();
    inp.open_field("qvnum");
    __deser(inp,res.qvnum);
    inp.close_field();
    inp.close_struct();
}
template <>
craq_system::msg_type _arg<craq_system::msg_type>(std::vector<ivy_value> &args, unsigned idx, long long bound){
    ivy_value &arg = args[idx];
    if (arg.atom.size() == 0 || arg.fields.size() != 0) throw out_of_bounds(idx,arg.pos);
    if(arg.atom == "request") return craq_system::msg_type__request;
    if(arg.atom == "reply") return craq_system::msg_type__reply;
    if(arg.atom == "inquire") return craq_system::msg_type__inquire;
    if(arg.atom == "inform") return craq_system::msg_type__inform;
    if(arg.atom == "commitAck") return craq_system::msg_type__commitAck;
    if(arg.atom == "ack") return craq_system::msg_type__ack;
    throw out_of_bounds("bad value: " + arg.atom,arg.pos);
}
template <>
void __deser<craq_system::msg_type>(ivy_deser &inp, craq_system::msg_type &res){
    int __res;
    __deser(inp,__res);
    res = (craq_system::msg_type)__res;
}
template <>
craq_system::query_type _arg<craq_system::query_type>(std::vector<ivy_value> &args, unsigned idx, long long bound){
    ivy_value &arg = args[idx];
    if (arg.atom.size() == 0 || arg.fields.size() != 0) throw out_of_bounds(idx,arg.pos);
    if(arg.atom == "read") return craq_system::read;
    if(arg.atom == "write") return craq_system::write;
    throw out_of_bounds("bad value: " + arg.atom,arg.pos);
}
template <>
void __deser<craq_system::query_type>(ivy_deser &inp, craq_system::query_type &res){
    int __res;
    __deser(inp,__res);
    res = (craq_system::query_type)__res;
}


class stdin_reader: public reader {
    std::string buf;
    std::string eof_flag;

public:
    bool eof(){
      return eof_flag.size();
    }
    virtual int fdes(){
        return 0;
    }
    virtual void read() {
        char tmp[257];
        int chars = ::read(0,tmp,256);
        if (chars == 0) {  // EOF
            if (buf.size())
                process(buf);
            eof_flag = "eof";
        }
        tmp[chars] = 0;
        buf += std::string(tmp);
        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0,pos+1);
            buf.erase(0,pos+1);
            process(line);
        }
    }
    virtual void process(const std::string &line) {
        __ivy_out << line;
    }
};

class cmd_reader: public stdin_reader {
    int lineno;
public:
    craq_system_repl &ivy;    

    cmd_reader(craq_system_repl &_ivy) : ivy(_ivy) {
        lineno = 1;
        if (isatty(fdes()))
            __ivy_out << "> "; __ivy_out.flush();
    }

    virtual void process(const std::string &cmd) {
        std::string action;
        std::vector<ivy_value> args;
        try {
            parse_command(cmd,action,args);
            ivy.__lock();

                if (action == "system.server.get") {
                    check_arity(args,1,action);
                    ivy.ext__system__server__get(_arg<unsigned long long>(args,0,0));
                }
                else
    
                if (action == "system.server.set") {
                    check_arity(args,2,action);
                    ivy.ext__system__server__set(_arg<unsigned long long>(args,0,0),_arg<__strlit>(args,1,0));
                }
                else
    
                if (action == "trans.mq.delete_all") {
                    check_arity(args,2,action);
                    ivy.ext__trans__mq__delete_all(_arg<unsigned>(args,0,32),_arg<unsigned long long>(args,1,0));
                }
                else
    
                if (action == "trans.mq.empty") {
                    check_arity(args,1,action);
                    __ivy_out  << "= " << ivy.ext__trans__mq__empty(_arg<unsigned>(args,0,32)) << std::endl;
                }
                else
    
                if (action == "trans.mq.enqueue") {
                    check_arity(args,2,action);
                    ivy.ext__trans__mq__enqueue(_arg<unsigned>(args,0,32),_arg<craq_system::msg>(args,1,0));
                }
                else
    
                if (action == "trans.mq.pick_one") {
                    check_arity(args,1,action);
                    __ivy_out  << "= " << ivy.ext__trans__mq__pick_one(_arg<unsigned>(args,0,32)) << std::endl;
                }
                else
    
            {
                std::cerr << "undefined action: " << action << std::endl;
            }
            ivy.__unlock();
        }
        catch (syntax_error& err) {
            ivy.__unlock();
            std::cerr << "line " << lineno << ":" << err.pos << ": syntax error" << std::endl;
        }
        catch (out_of_bounds &err) {
            ivy.__unlock();
            std::cerr << "line " << lineno << ":" << err.pos << ": " << err.txt << " bad value" << std::endl;
        }
        catch (bad_arity &err) {
            ivy.__unlock();
            std::cerr << "action " << err.action << " takes " << err.num  << " input parameters" << std::endl;
        }
        if (isatty(fdes()))
            __ivy_out << "> "; __ivy_out.flush();
        lineno++;
    }
};



int main(int argc, char **argv){
        int test_iters = 100;
        int runs = 1;
    unsigned p__node__size;
    unsigned p__me;

    int seed = 1;
    int sleep_ms = 10;
    int final_ms = 0; 
    
    std::vector<char *> pargs; // positional args
    pargs.push_back(argv[0]);
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        size_t p = arg.find('=');
        if (p == std::string::npos)
            pargs.push_back(argv[i]);
        else {
            std::string param = arg.substr(0,p);
            std::string value = arg.substr(p+1);

            if (param == "out") {
                __ivy_out.open(value.c_str());
                if (!__ivy_out) {
                    std::cerr << "cannot open to write: " << value << std::endl;
                    return 1;
                }
            }
            else if (param == "iters") {
                test_iters = atoi(value.c_str());
            }
            else if (param == "runs") {
                runs = atoi(value.c_str());
            }
            else if (param == "seed") {
                seed = atoi(value.c_str());
            }
            else if (param == "delay") {
                sleep_ms = atoi(value.c_str());
            }
            else if (param == "wait") {
                final_ms = atoi(value.c_str());
            }
            else if (param == "modelfile") {
                __ivy_modelfile.open(value.c_str());
                if (!__ivy_modelfile) {
                    std::cerr << "cannot open to write: " << value << std::endl;
                    return 1;
                }
            }
            else {
                std::cerr << "unknown option: " << param << std::endl;
                return 1;
            }
        }
    }
    srand(seed);
    if (!__ivy_out.is_open())
        __ivy_out.basic_ios<char>::rdbuf(std::cout.rdbuf());
    argc = pargs.size();
    argv = &pargs[0];
    if (argc == 4){
        argc--;
        int fd = _open(argv[argc],0);
        if (fd < 0){
            std::cerr << "cannot open to read: " << argv[argc] << "\n";
            __ivy_exit(1);
        }
        _dup2(fd, 0);
    }
    if (argc != 3){
        std::cerr << "usage: craq_system node.size me\n";
        __ivy_exit(1);
    }
    std::vector<std::string> args;
    std::vector<ivy_value> arg_values(2);
    for(int i = 1; i < argc;i++){args.push_back(argv[i]);}
    try {
        int pos = 0;
        arg_values[0] = parse_value(args[0],pos);
        p__node__size =  _arg<unsigned>(arg_values,0,32);
    }
    catch(out_of_bounds &) {
        std::cerr << "parameter node__size out of bounds\n";
        __ivy_exit(1);
    }
    catch(syntax_error &) {
        std::cerr << "syntax error in command argument\n";
        __ivy_exit(1);
    }
    try {
        int pos = 0;
        arg_values[1] = parse_value(args[1],pos);
        p__me =  _arg<unsigned>(arg_values,1,32);
    }
    catch(out_of_bounds &) {
        std::cerr << "parameter me out of bounds\n";
        __ivy_exit(1);
    }
    catch(syntax_error &) {
        std::cerr << "syntax error in command argument\n";
        __ivy_exit(1);
    }

#ifdef _WIN32
    // Boilerplate from windows docs

    {
        WORD wVersionRequested;
        WSADATA wsaData;
        int err;

    /* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
        wVersionRequested = MAKEWORD(2, 2);

        err = WSAStartup(wVersionRequested, &wsaData);
        if (err != 0) {
            /* Tell the user that we could not find a usable */
            /* Winsock DLL.                                  */
            printf("WSAStartup failed with error: %d\n", err);
            return 1;
        }

    /* Confirm that the WinSock DLL supports 2.2.*/
    /* Note that if the DLL supports versions greater    */
    /* than 2.2 in addition to 2.2, it will still return */
    /* 2.2 in wVersion since that is the version we      */
    /* requested.                                        */

        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
            /* Tell the user that we could not find a usable */
            /* WinSock DLL.                                  */
            printf("Could not find a usable version of Winsock.dll\n");
            WSACleanup();
            return 1;
        }
    }
#endif
    craq_system_repl ivy(p__node__size,p__me);
    for(unsigned i = 0; i < argc; i++) {ivy.__argv.push_back(argv[i]);}
    ivy.__init();


    ivy.__unlock();

    cmd_reader *cr = new cmd_reader(ivy);

    // The main thread runs the console reader

    while (!cr->eof())
        cr->read();
    return 0;

    return 0;
}
