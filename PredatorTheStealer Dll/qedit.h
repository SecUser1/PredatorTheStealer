///////////////////////////////////////////////////////////////////////////////////

#include <Unknwn.h>
#include <strmif.h>

#pragma comment(lib, "strmiids.lib")

#ifndef __qedit_h__
#define __qedit_h__

///////////////////////////////////////////////////////////////////////////////////

#pragma once

///////////////////////////////////////////////////////////////////////////////////

struct __declspec(uuid("0579154a-2b53-4994-b0d0-e773148eff85"))
	ISampleGrabberCB : IUnknown
{
	//
	// Raw methods provided by interface
	//

	virtual HRESULT __stdcall SampleCB(
		double SampleTime,
		struct IMediaSample * pSample) = 0;
	virtual HRESULT __stdcall BufferCB(
		double SampleTime,
		unsigned char * pBuffer,
		long BufferLen) = 0;
};




struct __declspec(uuid("6b652fff-11fe-4fce-92ad-0266b5d7c78f"))
	ISampleGrabber : IUnknown
{
	//
	// Raw methods provided by interface
	//

	virtual HRESULT __stdcall SetOneShot(
		long OneShot) = 0;
	virtual HRESULT __stdcall SetMediaType(
		struct _AMMediaType * pType) = 0;
	virtual HRESULT __stdcall GetConnectedMediaType(
		struct _AMMediaType * pType) = 0;
	virtual HRESULT __stdcall SetBufferSamples(
		long BufferThem) = 0;
	virtual HRESULT __stdcall GetCurrentBuffer(
		/*[in,out]*/ long * pBufferSize,
		/*[out]*/ long * pBuffer) = 0;
	virtual HRESULT __stdcall GetCurrentSample(
		/*[out,retval]*/ struct IMediaSample * * ppSample) = 0;
	virtual HRESULT __stdcall SetCallback(
		struct ISampleGrabberCB * pCallback,
		long WhichMethodToCallback) = 0;
};


static const IID IID_ISampleGrabber = { 0x6B652FFF, 0x11FE, 0x4fce,{ 0x92, 0xAD, 0x02, 0x66, 0xB5, 0xD7, 0xC7, 0x8F } };
static const IID IID_ISampleGrabberCB = { 0x0579154A, 0x2B53, 0x4994,{ 0xB0, 0xD0, 0xE7, 0x73, 0x14, 0x8E, 0xFF, 0x85 } };
static const CLSID CLSID_SampleGrabber = { 0xC1F400A0, 0x3F08, 0x11d3,{ 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };
static const CLSID CLSID_NullRenderer = { 0xC1F400A4, 0x3F08, 0x11d3,{ 0x9F, 0x0B, 0x00, 0x60, 0x08, 0x03, 0x9E, 0x37 } };

#endif
