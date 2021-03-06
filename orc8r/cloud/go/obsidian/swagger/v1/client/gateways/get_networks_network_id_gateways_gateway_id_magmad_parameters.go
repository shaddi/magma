// Code generated by go-swagger; DO NOT EDIT.

package gateways

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

// NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParams creates a new GetNetworksNetworkIDGatewaysGatewayIDMagmadParams object
// with the default values initialized.
func NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParams() *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	var ()
	return &GetNetworksNetworkIDGatewaysGatewayIDMagmadParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParamsWithTimeout creates a new GetNetworksNetworkIDGatewaysGatewayIDMagmadParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParamsWithTimeout(timeout time.Duration) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	var ()
	return &GetNetworksNetworkIDGatewaysGatewayIDMagmadParams{

		timeout: timeout,
	}
}

// NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParamsWithContext creates a new GetNetworksNetworkIDGatewaysGatewayIDMagmadParams object
// with the default values initialized, and the ability to set a context for a request
func NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParamsWithContext(ctx context.Context) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	var ()
	return &GetNetworksNetworkIDGatewaysGatewayIDMagmadParams{

		Context: ctx,
	}
}

// NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParamsWithHTTPClient creates a new GetNetworksNetworkIDGatewaysGatewayIDMagmadParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewGetNetworksNetworkIDGatewaysGatewayIDMagmadParamsWithHTTPClient(client *http.Client) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	var ()
	return &GetNetworksNetworkIDGatewaysGatewayIDMagmadParams{
		HTTPClient: client,
	}
}

/*GetNetworksNetworkIDGatewaysGatewayIDMagmadParams contains all the parameters to send to the API endpoint
for the get networks network ID gateways gateway ID magmad operation typically these are written to a http.Request
*/
type GetNetworksNetworkIDGatewaysGatewayIDMagmadParams struct {

	/*GatewayID
	  Gateway ID

	*/
	GatewayID string
	/*NetworkID
	  Network ID

	*/
	NetworkID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) WithTimeout(timeout time.Duration) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) WithContext(ctx context.Context) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) WithHTTPClient(client *http.Client) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGatewayID adds the gatewayID to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) WithGatewayID(gatewayID string) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	o.SetGatewayID(gatewayID)
	return o
}

// SetGatewayID adds the gatewayId to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) SetGatewayID(gatewayID string) {
	o.GatewayID = gatewayID
}

// WithNetworkID adds the networkID to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) WithNetworkID(networkID string) *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams {
	o.SetNetworkID(networkID)
	return o
}

// SetNetworkID adds the networkId to the get networks network ID gateways gateway ID magmad params
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) SetNetworkID(networkID string) {
	o.NetworkID = networkID
}

// WriteToRequest writes these params to a swagger request
func (o *GetNetworksNetworkIDGatewaysGatewayIDMagmadParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param gateway_id
	if err := r.SetPathParam("gateway_id", o.GatewayID); err != nil {
		return err
	}

	// path param network_id
	if err := r.SetPathParam("network_id", o.NetworkID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
