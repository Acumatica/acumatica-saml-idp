using System;
using System.IO;
using System.IO.Compression;
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

public partial class Page_LogoutSaml : Page
{
	protected void Page_Load(object sender, EventArgs e)
	{
	    var decodedXmlData = Saml2Binding.Get(Saml2BindingType.HttpRedirect).Unbind(new HttpRequestData(new HttpRequestWrapper(Request)));
		var request = Saml2LogoutRequest.Read(decodedXmlData);

		if (request == null) throw new PXException("Invalid Saml request.");

		//As a security precaution, we don't allow blind redirects - only *.acumatica.com is allowed.
		if (String.IsNullOrEmpty(Request.QueryString["RelayState"])) throw new Exception("RelayState missing.");
		var redirectUrl = new System.Uri(Request.QueryString["RelayState"]);
		if(!redirectUrl.Host.EndsWith("acumatica.com")) throw new Exception("Unauthorized redirect URL");

		//Code to logout was taken from Main.aspx.cs.
		PX.Data.PXLogin.LogoutUser(PXAccess.GetUserName(), Session.SessionID);
		PXContext.Session.SetString("UserLogin", string.Empty); // this session variable is used in global.asax
		string absoluteLoginUrl = PX.Export.Authentication.AuthenticationManagerModule.Instance.SignOut();
		Session.Abandon();

		var signingCertificate = new X509Certificate2(HttpContext.Current.Server.MapPath(@"Saml.pfx"), "", 
		    X509KeyStorageFlags.MachineKeySet);
		
		var response = new Saml2LogoutResponse(
			new EntityId("http://www.acumatica.com"),
			signingCertificate, new Uri(redirectUrl, "wp-login.php?saml_sls"), 
			request.Id);

		Response.Redirect(response.DestinationUri + "&SAMLResponse=" + Serialize(response.ToXml()) + "&RelayState=" + Request.QueryString["RelayState"]);
	}
	
	private static string Serialize(string payload)
	{
	  using (var compressed = new MemoryStream())
	  {
	      using (var writer = new StreamWriter(new DeflateStream(compressed, CompressionLevel.Optimal, true)))
	      {
	          writer.Write(payload);
	      }

	      return HttpUtility.UrlEncode(Convert.ToBase64String(compressed.GetBuffer()));
	  }
	}
}