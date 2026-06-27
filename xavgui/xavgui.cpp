///////////////////////////////////////////////////////////////////////////
// C++ code generated with wxFormBuilder (version 4.2.1-0-g80c4cb6)
// http://www.wxformbuilder.org/
//
// PLEASE DO *NOT* EDIT THIS FILE!
///////////////////////////////////////////////////////////////////////////

#include "xavgui.h"

///////////////////////////////////////////////////////////////////////////

MainWindow::MainWindow( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxFrame( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* vbox;
	vbox = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* main_status_box;
	main_status_box = new wxBoxSizer( wxHORIZONTAL );

	security_status = new wxStaticBitmap( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxSize( 100,100 ), 0, wxT("security_status") );
	main_status_box->Add( security_status, 1, wxALIGN_CENTER|wxALL, 50 );

	wxBoxSizer* main_status_text;
	main_status_text = new wxBoxSizer( wxVERTICAL );

	protection_status = new wxStaticText( this, wxID_ANY, _("Your System is Protected"), wxDefaultPosition, wxDefaultSize, 0 );
	protection_status->Wrap( -1 );
	protection_status->SetFont( wxFont( 18, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Sans") ) );
	protection_status->SetForegroundColour( wxColour( 0, 185, 148 ) );

	main_status_text->Add( protection_status, 0, wxTOP, 50 );

	wxBoxSizer* realtime_protection_box;
	realtime_protection_box = new wxBoxSizer( wxHORIZONTAL );

	realtime_protection_label = new wxStaticText( this, wxID_ANY, _("Real-Time Protection:"), wxDefaultPosition, wxDefaultSize, 0 );
	realtime_protection_label->Wrap( -1 );
	realtime_protection_label->SetForegroundColour( wxColour( 45, 52, 54 ) );

	realtime_protection_box->Add( realtime_protection_label, 0, wxALL, 0 );

	realtime_protection_status = new wxStaticText( this, wxID_ANY, _("On"), wxDefaultPosition, wxDefaultSize, 0 );
	realtime_protection_status->Wrap( -1 );
	realtime_protection_status->SetForegroundColour( wxColour( 0, 184, 148 ) );

	realtime_protection_box->Add( realtime_protection_status, 0, wxLEFT, 5 );


	main_status_text->Add( realtime_protection_box, 0, wxEXPAND|wxTOP, 30 );

	wxBoxSizer* malware_database_box;
	malware_database_box = new wxBoxSizer( wxHORIZONTAL );

	malware_database_label = new wxStaticText( this, wxID_ANY, _("Malware Database Version:"), wxDefaultPosition, wxDefaultSize, 0 );
	malware_database_label->Wrap( -1 );
	malware_database_label->SetForegroundColour( wxColour( 45, 52, 54 ) );

	malware_database_box->Add( malware_database_label, 0, wxALL, 0 );

	malware_database_version = new wxStaticText( this, wxID_ANY, _("2026.06.27.v03"), wxDefaultPosition, wxDefaultSize, 0 );
	malware_database_version->Wrap( -1 );
	malware_database_version->SetForegroundColour( wxColour( 0, 184, 148 ) );

	malware_database_box->Add( malware_database_version, 0, wxLEFT, 5 );


	main_status_text->Add( malware_database_box, 0, wxEXPAND|wxTOP, 5 );

	wxBoxSizer* engine_status_box;
	engine_status_box = new wxBoxSizer( wxHORIZONTAL );

	engine_status_label = new wxStaticText( this, wxID_ANY, _("Engine Status:"), wxDefaultPosition, wxDefaultSize, 0 );
	engine_status_label->Wrap( -1 );
	engine_status_label->SetForegroundColour( wxColour( 45, 52, 54 ) );

	engine_status_box->Add( engine_status_label, 0, wxALL, 0 );

	xav_engine_status = new wxStaticText( this, wxID_ANY, _("Xav"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL );
	xav_engine_status->Wrap( -1 );
	xav_engine_status->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
	xav_engine_status->SetBackgroundColour( wxColour( 0, 184, 148 ) );

	engine_status_box->Add( xav_engine_status, 2, wxLEFT, 5 );

	clamav_engine_status1 = new wxStaticText( this, wxID_ANY, _("ClamAV"), wxDefaultPosition, wxDefaultSize, wxALIGN_CENTER_HORIZONTAL );
	clamav_engine_status1->Wrap( -1 );
	clamav_engine_status1->SetForegroundColour( wxSystemSettings::GetColour( wxSYS_COLOUR_WINDOW ) );
	clamav_engine_status1->SetBackgroundColour( wxColour( 178, 190, 195 ) );

	engine_status_box->Add( clamav_engine_status1, 2, wxLEFT, 5 );


	engine_status_box->Add( 0, 0, 3, wxEXPAND, 5 );


	main_status_text->Add( engine_status_box, 0, wxEXPAND|wxTOP, 5 );

	wxBoxSizer* button_box;
	button_box = new wxBoxSizer( wxHORIZONTAL );

	update_btn = new wxButton( this, wxID_ANY, _(" &Update"), wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, wxT("update_btn") );
	button_box->Add( update_btn, 0, 0, 15 );

	scan_btn = new wxButton( this, wxID_ANY, _(" &Scan"), wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, wxT("scan_btn") );
	button_box->Add( scan_btn, 0, wxLEFT, 15 );

	settings_btn = new wxButton( this, wxID_ANY, _(" &Settings"), wxDefaultPosition, wxDefaultSize, 0, wxDefaultValidator, wxT("settings_btn") );
	button_box->Add( settings_btn, 0, wxLEFT, 15 );


	main_status_text->Add( button_box, 1, wxEXPAND|wxTOP, 25 );


	main_status_box->Add( main_status_text, 2, wxEXPAND, 5 );


	vbox->Add( main_status_box, 1, wxEXPAND, 5 );


	this->SetSizer( vbox );
	this->Layout();

	this->Centre( wxBOTH );
}

MainWindow::~MainWindow()
{
}

ScanWindow::ScanWindow( wxWindow* parent, wxWindowID id, const wxString& title, const wxPoint& pos, const wxSize& size, long style ) : wxFrame( parent, id, title, pos, size, style )
{
	this->SetSizeHints( wxDefaultSize, wxDefaultSize );

	wxBoxSizer* vbox;
	vbox = new wxBoxSizer( wxVERTICAL );

	wxBoxSizer* icon_and_user_options_box;
	icon_and_user_options_box = new wxBoxSizer( wxHORIZONTAL );

	scan_icon = new wxStaticBitmap( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, 0 );
	icon_and_user_options_box->Add( scan_icon, 1, wxALIGN_CENTER|wxALL, 30 );

	wxBoxSizer* user_options_box;
	user_options_box = new wxBoxSizer( wxVERTICAL );

	choose_label = new wxStaticText( this, wxID_ANY, _("Choose Scan Type:"), wxDefaultPosition, wxDefaultSize, 0 );
	choose_label->Wrap( -1 );
	user_options_box->Add( choose_label, 0, wxTOP, 20 );

	wxBoxSizer* choice_box;
	choice_box = new wxBoxSizer( wxHORIZONTAL );

	wxString choicesChoices[] = { _("Quick Scan - Only scan critical area"), _("Full Scan - Scan the whole system"), _("Custom Scan") };
	int choicesNChoices = sizeof( choicesChoices ) / sizeof( wxString );
	choices = new wxChoice( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, choicesNChoices, choicesChoices, 0 );
	choices->SetSelection( 0 );
	choice_box->Add( choices, 2, 0, 10 );


	choice_box->Add( 0, 0, 1, wxEXPAND, 5 );


	user_options_box->Add( choice_box, 0, wxEXPAND|wxTOP, 10 );

	wxBoxSizer* btn_box;
	btn_box = new wxBoxSizer( wxHORIZONTAL );

	start_scan_btn = new wxButton( this, wxID_ANY, _("Start Scan"), wxDefaultPosition, wxDefaultSize, 0 );
	btn_box->Add( start_scan_btn, 0, 0, 10 );

	pause_btn = new wxBitmapButton( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, wxBU_AUTODRAW|0 );
	pause_btn->Enable( false );

	btn_box->Add( pause_btn, 0, wxLEFT, 10 );

	cancel_btn = new wxBitmapButton( this, wxID_ANY, wxNullBitmap, wxDefaultPosition, wxDefaultSize, wxBU_AUTODRAW|0 );
	cancel_btn->Enable( false );

	btn_box->Add( cancel_btn, 0, wxLEFT, 10 );


	user_options_box->Add( btn_box, 1, wxEXPAND|wxTOP, 10 );


	icon_and_user_options_box->Add( user_options_box, 4, wxEXPAND, 5 );


	vbox->Add( icon_and_user_options_box, 1, wxEXPAND, 5 );

	wxBoxSizer* scan_result_box;
	scan_result_box = new wxBoxSizer( wxVERTICAL );

	scan_progress = new wxGauge( this, wxID_ANY, 100, wxDefaultPosition, wxDefaultSize, wxGA_HORIZONTAL );
	scan_progress->SetValue( 27 );
	scan_result_box->Add( scan_progress, 0, wxALL|wxEXPAND, 15 );

	wxBoxSizer* curr_file_box;
	curr_file_box = new wxBoxSizer( wxHORIZONTAL );

	curr_file_label = new wxStaticText( this, wxID_ANY, _("Current scanning file:"), wxDefaultPosition, wxDefaultSize, 0 );
	curr_file_label->Wrap( -1 );
	curr_file_box->Add( curr_file_label, 0, wxLEFT, 15 );

	curr_file = new wxStaticText( this, wxID_ANY, _("/bin/cat"), wxDefaultPosition, wxDefaultSize, 0 );
	curr_file->Wrap( -1 );
	curr_file_box->Add( curr_file, 1, wxLEFT|wxRIGHT, 10 );


	scan_result_box->Add( curr_file_box, 0, wxEXPAND, 5 );

	wxBoxSizer* scan_result_list_box;
	scan_result_list_box = new wxBoxSizer( wxVERTICAL );

	scan_result_list = new wxListCtrl( this, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxLC_REPORT );
	scan_result_list_box->Add( scan_result_list, 0, wxEXPAND|wxLEFT|wxRIGHT, 10 );


	scan_result_box->Add( scan_result_list_box, 1, wxBOTTOM|wxEXPAND|wxTOP, 10 );


	vbox->Add( scan_result_box, 1, wxEXPAND, 5 );


	this->SetSizer( vbox );
	this->Layout();

	this->Centre( wxBOTH );
}

ScanWindow::~ScanWindow()
{
}
