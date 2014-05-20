#ifndef TIMEVAL_HH
#define TIMEVAL_HH 1

#include <sys/time.h>

long long int time_msec();

struct timeval do_gettimeofday(bool update = false);
::timeval operator+(const ::timeval&, const ::timeval&);
::timeval operator-(const ::timeval&, const ::timeval&);
const ::timeval& operator+=(::timeval&, const ::timeval&);
const ::timeval& operator-=(::timeval&, const ::timeval&);
int timeval_compare(const ::timeval&, const ::timeval&);

double timeval_to_double(const ::timeval&);
double timespec_to_double(const ::timespec&);

static inline timeval make_timeval(unsigned long int tv_sec,
                                   unsigned long int tv_usec)
{
    timeval tv;
    tv.tv_sec = tv_sec;
    tv.tv_usec = tv_usec;
    return tv;
}

static inline timespec make_timespec(unsigned long int tv_sec,
                                     unsigned long int tv_nsec)
{
    timespec ts;
    ts.tv_sec = tv_sec;
    ts.tv_nsec = tv_nsec;
    return ts;
}

long int timeval_to_ms(const ::timeval&);
::timeval timeval_from_ms(long int ms);
long int timespec_to_ms(const ::timespec&);
::timespec timespec_from_ms(long int ms);

static inline bool operator==(const ::timeval& x, const ::timeval& y)
{
    return timeval_compare(x, y) == 0;
}

static inline bool operator!=(const ::timeval& x, const ::timeval& y)
{
    return timeval_compare(x, y) != 0;
}

static inline bool operator<(const ::timeval& x, const ::timeval& y)
{
    return timeval_compare(x, y) < 0;
}

static inline bool operator>(const ::timeval& x, const ::timeval& y)
{
    return timeval_compare(x, y) > 0;
}

static inline bool operator<=(const ::timeval& x, const ::timeval& y)
{
    return timeval_compare(x, y) <= 0;
}

static inline bool operator>=(const ::timeval& x, const ::timeval& y)
{
    return timeval_compare(x, y) >= 0;
}

#endif /* timeval.hh */
