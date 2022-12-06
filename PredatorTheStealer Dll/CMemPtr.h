#pragma once

class CMemPtr
{
private:
    void** m_ptr;
    bool watchActive;

public:
    CMemPtr(void** ptr) : m_ptr(ptr), watchActive(true) {}

    ~CMemPtr()
    {
        if (*m_ptr && watchActive)
        { 
            free(*m_ptr); 
            *m_ptr = 0; 
        } 
    }

    void disableWatch() { watchActive = false; }
};

#define WATCH(ptr) \
    CMemPtr watch_##ptr((void**)&ptr)

#define DISABLE_WATCH(ptr) \
    watch_##ptr.disableWatch()
