// Code generated by go-swagger; DO NOT EDIT.

package wifi_gateways

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"
)

// NewGetWifiNetworkIDGatewaysParams creates a new GetWifiNetworkIDGatewaysParams object
// with the default values initialized.
func NewGetWifiNetworkIDGatewaysParams() *GetWifiNetworkIDGatewaysParams {
	var ()
	return &GetWifiNetworkIDGatewaysParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetWifiNetworkIDGatewaysParamsWithTimeout creates a new GetWifiNetworkIDGatewaysParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetWifiNetworkIDGatewaysParamsWithTimeout(timeout time.Duration) *GetWifiNetworkIDGatewaysParams {
	var ()
	return &GetWifiNetworkIDGatewaysParams{

		timeout: timeout,
	}
}

// NewGetWifiNetworkIDGatewaysParamsWithContext creates a new GetWifiNetworkIDGatewaysParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetWifiNetworkIDGatewaysParamsWithContext(ctx context.Context) *GetWifiNetworkIDGatewaysParams {
	var ()
	return &GetWifiNetworkIDGatewaysParams{

		Context: ctx,
	}
}

// NewGetWifiNetworkIDGatewaysParamsWithHTTPClient creates a new GetWifiNetworkIDGatewaysParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetWifiNetworkIDGatewaysParamsWithHTTPClient(client *http.Client) *GetWifiNetworkIDGatewaysParams {
	var ()
	return &GetWifiNetworkIDGatewaysParams{
		HTTPClient: client,
	}
}

/*GetWifiNetworkIDGatewaysParams contains all the parameters to send to the API endpoint
for the get wifi network ID gateways operation typically these are written to a http.Request
*/
type GetWifiNetworkIDGatewaysParams struct {

	/*NetworkID
	  Network ID

	*/
	NetworkID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) WithTimeout(timeout time.Duration) *GetWifiNetworkIDGatewaysParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) WithContext(ctx context.Context) *GetWifiNetworkIDGatewaysParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) WithHTTPClient(client *http.Client) *GetWifiNetworkIDGatewaysParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithNetworkID adds the networkID to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) WithNetworkID(networkID string) *GetWifiNetworkIDGatewaysParams {
	o.SetNetworkID(networkID)
	return o
}

// SetNetworkID adds the networkId to the get wifi network ID gateways params
func (o *GetWifiNetworkIDGatewaysParams) SetNetworkID(networkID string) {
	o.NetworkID = networkID
}

// WriteToRequest writes these params to a swagger request
func (o *GetWifiNetworkIDGatewaysParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param network_id
	if err := r.SetPathParam("network_id", o.NetworkID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
