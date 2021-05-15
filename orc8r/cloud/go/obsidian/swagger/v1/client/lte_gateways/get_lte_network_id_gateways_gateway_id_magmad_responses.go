// Code generated by go-swagger; DO NOT EDIT.

package lte_gateways

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"

	strfmt "github.com/go-openapi/strfmt"

	models "magma/orc8r/cloud/go/obsidian/swagger/v1/models"
)

// GetLTENetworkIDGatewaysGatewayIDMagmadReader is a Reader for the GetLTENetworkIDGatewaysGatewayIDMagmad structure.
type GetLTENetworkIDGatewaysGatewayIDMagmadReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetLTENetworkIDGatewaysGatewayIDMagmadReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetLTENetworkIDGatewaysGatewayIDMagmadOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGetLTENetworkIDGatewaysGatewayIDMagmadDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetLTENetworkIDGatewaysGatewayIDMagmadOK creates a GetLTENetworkIDGatewaysGatewayIDMagmadOK with default headers values
func NewGetLTENetworkIDGatewaysGatewayIDMagmadOK() *GetLTENetworkIDGatewaysGatewayIDMagmadOK {
	return &GetLTENetworkIDGatewaysGatewayIDMagmadOK{}
}

/*GetLTENetworkIDGatewaysGatewayIDMagmadOK handles this case with default header values.

Magmad agent configuration
*/
type GetLTENetworkIDGatewaysGatewayIDMagmadOK struct {
	Payload *models.MagmadGatewayConfigs
}

func (o *GetLTENetworkIDGatewaysGatewayIDMagmadOK) Error() string {
	return fmt.Sprintf("[GET /lte/{network_id}/gateways/{gateway_id}/magmad][%d] getLteNetworkIdGatewaysGatewayIdMagmadOK  %+v", 200, o.Payload)
}

func (o *GetLTENetworkIDGatewaysGatewayIDMagmadOK) GetPayload() *models.MagmadGatewayConfigs {
	return o.Payload
}

func (o *GetLTENetworkIDGatewaysGatewayIDMagmadOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MagmadGatewayConfigs)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetLTENetworkIDGatewaysGatewayIDMagmadDefault creates a GetLTENetworkIDGatewaysGatewayIDMagmadDefault with default headers values
func NewGetLTENetworkIDGatewaysGatewayIDMagmadDefault(code int) *GetLTENetworkIDGatewaysGatewayIDMagmadDefault {
	return &GetLTENetworkIDGatewaysGatewayIDMagmadDefault{
		_statusCode: code,
	}
}

/*GetLTENetworkIDGatewaysGatewayIDMagmadDefault handles this case with default header values.

Unexpected Error
*/
type GetLTENetworkIDGatewaysGatewayIDMagmadDefault struct {
	_statusCode int

	Payload *models.Error
}

// Code gets the status code for the get LTE network ID gateways gateway ID magmad default response
func (o *GetLTENetworkIDGatewaysGatewayIDMagmadDefault) Code() int {
	return o._statusCode
}

func (o *GetLTENetworkIDGatewaysGatewayIDMagmadDefault) Error() string {
	return fmt.Sprintf("[GET /lte/{network_id}/gateways/{gateway_id}/magmad][%d] GetLTENetworkIDGatewaysGatewayIDMagmad default  %+v", o._statusCode, o.Payload)
}

func (o *GetLTENetworkIDGatewaysGatewayIDMagmadDefault) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetLTENetworkIDGatewaysGatewayIDMagmadDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}