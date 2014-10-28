using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.Security;
using PX.Common;
using PX.Data;
using PX.SM;
using PX.Web.UI;
using Kentor.AuthServices.Configuration;
using Kentor.AuthServices;
using System.Security.Claims;
using System.IdentityModel.Metadata;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

public partial class Page_LoginSaml : Page
{
	protected void Page_Load(object sender, EventArgs e)
	{
        var decodedXmlData = Saml2Binding.Get(Saml2BindingType.HttpRedirect).Unbind(new HttpRequestData(new HttpRequestWrapper(Request)));
	    var request = Saml2AuthenticationRequest.Read(decodedXmlData);
		
		if (request == null) throw new PXException("Invalid Saml request.");

        var userID = PXAccess.GetUserID();
        PX.SM.Users user = PXSelect<PX.SM.Users, Where<PX.SM.Users.pKID, Equal<Required<PX.SM.Users.pKID>>>>.Select(new PXGraph(), userID);
        if (user == null) throw new PXException("User not found in database.");

        var signingCertificate = new X509Certificate2(HttpContext.Current.Server.MapPath(@"Saml.pfx"), "", 
            X509KeyStorageFlags.MachineKeySet);

        var claims = new List<Claim>();
        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Username));
	    claims.Add(new Claim("username", user.Username));
        claims.Add(new Claim("email", user.Email));
        claims.Add(new Claim("firstName", user.FirstName));
        claims.Add(new Claim("lastName", user.LastName));
        claims.Add(new Claim("memberOf", "Default" /*"Wordpress Administrators"*/));

        var response = new Saml2Response(
            new EntityId("http://www.acumatica.com"),
            signingCertificate, request.AssertionConsumerServiceUrl,
            request.Id, new ClaimsIdentity(claims.ToArray()));

        var command = Saml2Binding.Get(Saml2BindingType.HttpPost).Bind(response);
		command.ContentType = "text/html";
        command.Apply(new HttpResponseWrapper(Response));
	}
}