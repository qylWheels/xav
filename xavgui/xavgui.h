///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version 4.2.1-0-g80c4cb6)
// http://www.wxformbuilder.org/
//
// PLEASE DO *NOT* EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#pragma once

#include <wx/artprov.h>
#include <wx/xrc/xmlres.h>
#include <wx/intl.h>
#include <wx/bitmap.h>
#include <wx/image.h>
#include <wx/icon.h>
#include <wx/statbmp.h>
#include <wx/gdicmn.h>
#include <wx/font.h>
#include <wx/colour.h>
#include <wx/settings.h>
#include <wx/string.h>
#include <wx/stattext.h>
#include <wx/sizer.h>
#include <wx/button.h>
#include <wx/frame.h>
#include <wx/choice.h>
#include <wx/bmpbuttn.h>
#include <wx/gauge.h>
#include <wx/listctrl.h>

///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
/// Class MainWindow
///////////////////////////////////////////////////////////////////////////////
class MainWindow : public wxFrame
{
	private:

	protected:
		wxStaticBitmap* security_status;
		wxStaticText* protection_status;
		wxStaticText* realtime_protection_label;
		wxStaticText* realtime_protection_status;
		wxStaticText* malware_database_label;
		wxStaticText* malware_database_version;
		wxStaticText* engine_status_label;
		wxStaticText* xav_engine_status;
		wxStaticText* clamav_engine_status1;
		wxButton* update_btn;
		wxButton* scan_btn;
		wxButton* settings_btn;

	public:

		MainWindow( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Xav"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 658,417 ), long style = wxCAPTION|wxCLOSE_BOX|wxMINIMIZE_BOX|wxSTAY_ON_TOP|wxTAB_TRAVERSAL );

		~MainWindow();

};

///////////////////////////////////////////////////////////////////////////////
/// Class ScanWindow
///////////////////////////////////////////////////////////////////////////////
class ScanWindow : public wxFrame
{
	private:

	protected:
		wxStaticBitmap* scan_icon;
		wxStaticText* choose_label;
		wxChoice* choices;
		wxButton* start_scan_btn;
		wxBitmapButton* pause_btn;
		wxBitmapButton* cancel_btn;
		wxGauge* scan_progress;
		wxStaticText* curr_file_label;
		wxStaticText* curr_file;
		wxListCtrl* scan_result_list;

	public:

		ScanWindow( wxWindow* parent, wxWindowID id = wxID_ANY, const wxString& title = _("Xav - Scan"), const wxPoint& pos = wxDefaultPosition, const wxSize& size = wxSize( 500,300 ), long style = wxCAPTION|wxCLOSE_BOX|wxMINIMIZE_BOX|wxTAB_TRAVERSAL );

		~ScanWindow();

};

