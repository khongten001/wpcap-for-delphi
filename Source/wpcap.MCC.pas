//*************************************************************
//                        WPCAP FOR DELPHI                    *
//				                                        			      *
//                     Freeware Library                       *
//                       For Delphi 10.4                      *
//                            by                              *
//                     Alessandro Mancini                     *
//				                                        			      *
//*************************************************************
{LICENSE:
THIS SOFTWARE IS PROVIDED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESSED OR IMPLIED INCLUDING BUT NOT LIMITED TO THE APPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
YOU ASSUME THE ENTIRE RISK AS TO THE ACCURACY AND THE USE OF THE SOFTWARE
AND ALL OTHER RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SOFTWARE
AND DOCUMENTATION. PRODUCTIONS DOES NOT WARRANT THAT THE SOFTWARE IS ERROR-FREE
OR WILL OPERATE WITHOUT INTERRUPTION. THE SOFTWARE IS NOT DESIGNED, INTENDED
OR LICENSED FOR USE IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE CONTROLS,
INCLUDING WITHOUT LIMITATION, THE DESIGN, CONSTRUCTION, MAINTENANCE OR
OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR COMMUNICATION SYSTEMS,
AIR TRAFFIC CONTROL, AND LIFE SUPPORT OR WEAPONS SYSTEMS. PRODUCTIONS SPECIFICALLY
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR SUCH PURPOSE.

You may use/change/modify the component under 1 conditions:
1. In your application, add credits to "WPCAP FOR DELPHI"
{*******************************************************************************}

unit wpcap.MCC;

interface
uses  
  wpcap.Types,wpcap.Geometry,wpcap.Conts;

CONST
  MCC_ROWS: array [0..199] of TMCCRow = (
    (MCC:	412;	COUNTRY:	'Afghanistan';						           	LATITUDINE:		34.51666;			LONGITUDINE:	69.183333),
    (MCC:	276;	COUNTRY:	'Albania';								           	LATITUDINE:		41.33165;			LONGITUDINE:	19.817222),
    (MCC:	603;	COUNTRY:	'Algeria';								           	LATITUDINE:		36.75;				LONGITUDINE:	3.05),
    (MCC:	213;	COUNTRY:	'Andorra';								           	LATITUDINE:		42.51968;			LONGITUDINE:	1.5216055),
    (MCC:	631;	COUNTRY:	'Angola';								             	LATITUDINE:		-8.83333;			LONGITUDINE:	13.233333),
    (MCC:	722;	COUNTRY:	'Argentina';							           	LATITUDINE:		-34.6;				LONGITUDINE:	-58.66666),
    (MCC:	283;	COUNTRY:	'Armenia';								           	LATITUDINE:		40.16666;			LONGITUDINE:	44.5),
    (MCC:	363;	COUNTRY:	'Aruba';								             	LATITUDINE:		12.51666;			LONGITUDINE:	-70.03333),
    (MCC:	505;	COUNTRY:	'Australia';							           	LATITUDINE:		-12.1666;			LONGITUDINE:	96.833333),
    (MCC:	232;	COUNTRY:	'Austria';								           	LATITUDINE:		48.20911;			LONGITUDINE:	16.373061),
    (MCC:	400;	COUNTRY:	'Azerbaijan';							           	LATITUDINE:		40.38333;			LONGITUDINE:	49.866666),
    (MCC:	426;	COUNTRY:	'Bahrain';								           	LATITUDINE:		26.23333;			LONGITUDINE:	50.566666),
    (MCC:	470;	COUNTRY:	'Bangladesh';							           	LATITUDINE:		23.71666;			LONGITUDINE:	90.4),
    (MCC:	257;	COUNTRY:	'Belarus';								           	LATITUDINE:		53.96778;			LONGITUDINE:	27.576555),
    (MCC:	206;	COUNTRY:	'Belgium';								           	LATITUDINE:		50.84236;			LONGITUDINE:	4.3677527),
    (MCC:	702;	COUNTRY:	'Belize';								             	LATITUDINE:		17.25;				LONGITUDINE:	-88.76666),
    (MCC:	616;	COUNTRY:	'Benin';								             	LATITUDINE:		6.483333;			LONGITUDINE:	2.6166666),
    (MCC:	402;	COUNTRY:	'Bhutan';								             	LATITUDINE:		27.48333;			LONGITUDINE:	89.6),
    (MCC:	736;	COUNTRY:	'Bolivia';								           	LATITUDINE:		-16.5;				LONGITUDINE:	-68.15),
    (MCC:	218;	COUNTRY:	'Bosnia and Herzegovina';	           	LATITUDINE:		43.86671;			LONGITUDINE:	18.421325),
    (MCC:	652;	COUNTRY:	'Botswana';								           	LATITUDINE:		-24.75;				LONGITUDINE:	25.916666),
    (MCC:	724;	COUNTRY:	'Brazil';								             	LATITUDINE:		-15.7833;			LONGITUDINE:	-47.91666),
    (MCC:	528;	COUNTRY:	'Brunei';								             	LATITUDINE:		4.883333;			LONGITUDINE:	114.93333),
    (MCC:	284;	COUNTRY:	'Bulgaria';								           	LATITUDINE:		42.70968;			LONGITUDINE:	23.3226),
    (MCC:	613;	COUNTRY:	'Burkina Faso';					 	           	LATITUDINE:		12.36666;			LONGITUDINE:	-1.516666),
    (MCC:	642;	COUNTRY:	'Burundi';								           	LATITUDINE:		-3.36666;			LONGITUDINE:	29.35),
    (MCC:	456;	COUNTRY:	'Cambodia';								           	LATITUDINE:		11.55;				LONGITUDINE:	104.91666),
    (MCC:	624;	COUNTRY:	'Cameroon';								           	LATITUDINE:		3.866666;			LONGITUDINE:	11.516666),
    (MCC:	302;	COUNTRY:	'Canada';								             	LATITUDINE:		-4.31666;			LONGITUDINE:	15.3),
    (MCC:	625;	COUNTRY:	'Cape Verde';							           	LATITUDINE:		14.91666;			LONGITUDINE:	-23.51666),
    (MCC:	623;	COUNTRY:	'Central African Republic';          	LATITUDINE:		4.366666;			LONGITUDINE:	18.583333),
    (MCC:	622;	COUNTRY:	'Chad';									             	LATITUDINE:		12.1;			  	LONGITUDINE:	15.033333),
    (MCC:	730;	COUNTRY:	'Chile';								             	LATITUDINE:		-33.45;				LONGITUDINE:	-70.66666),
    (MCC:	732;	COUNTRY:	'Colombia';								           	LATITUDINE:		4.6;			  	LONGITUDINE:	-74.08333),
    (MCC:	654;	COUNTRY:	'Comoros';								           	LATITUDINE:		-11.7;				LONGITUDINE:	43.233333),
    (MCC:	712;	COUNTRY:	'Costa Rica';							           	LATITUDINE:		9.933333;			LONGITUDINE:	-84.08333),
    (MCC:	219;	COUNTRY:	'Croatia';								           	LATITUDINE:		45.82688;			LONGITUDINE:	15.978241),
    (MCC:	368;	COUNTRY:	'Cuba';									             	LATITUDINE:		23.11666;			LONGITUDINE:	-82.35),
    (MCC:	280;	COUNTRY:	'Cyprus';								             	LATITUDINE:		35.16801;			LONGITUDINE:	33.373633),
    (MCC:	230;	COUNTRY:	'Czech Republic';				 	           	LATITUDINE:		50.09327;			LONGITUDINE:	14.420241),
    (MCC:	630;	COUNTRY:	'Democratic Republic of the Congo';		LATITUDINE:		-4.25;				LONGITUDINE:	15.283333),
    (MCC:	238;	COUNTRY:	'Denmark';								          	LATITUDINE:		55.67855;			LONGITUDINE:	12.568016),
    (MCC:	638;	COUNTRY:	'Djibouti';								          	LATITUDINE:		11.58333;			LONGITUDINE:	43.15),
    (MCC:	370;	COUNTRY:	'Dominican Republic';			          	LATITUDINE:		-20.8666;			LONGITUDINE:	55.466666),
    (MCC:	514;	COUNTRY:	'East Timor';							          	LATITUDINE:		-8.58333;			LONGITUDINE:	125.6),
    (MCC:	740;	COUNTRY:	'Ecuador';								          	LATITUDINE:		-0.216666;	 	LONGITUDINE:	-78.5),
    (MCC:	602;	COUNTRY:	'Egypt';									            LATITUDINE:		30.05;				LONGITUDINE:	31.25),
    (MCC:	706;	COUNTRY:	'El Salvador';						          	LATITUDINE:		13.7;		   		LONGITUDINE:	-89.2),
    (MCC:	627;	COUNTRY:	'Equatorial Guinea';			          	LATITUDINE:		3.75;		   		LONGITUDINE:	8.7833333),
    (MCC:	657;	COUNTRY:	'Eritrea';								          	LATITUDINE:		15.33333;			LONGITUDINE:	38.933333),
    (MCC:	248;	COUNTRY:	'Estonia';								          	LATITUDINE:		59.44298;			LONGITUDINE:	24.754258),
    (MCC:	653;	COUNTRY:	'eSwatini';								          	LATITUDINE:		-26.3;				LONGITUDINE:	31.1),
    (MCC:	636;	COUNTRY:	'Ethiopia';								          	LATITUDINE:		9.033333;			LONGITUDINE:	38.7),
    (MCC:	750;	COUNTRY:	'Falkland Islands';				          	LATITUDINE:		-51.7;				LONGITUDINE:	-57.85),
    (MCC:	288;	COUNTRY:	'Faroe Islands';					          	LATITUDINE:		62.01666;			LONGITUDINE:	-6.766666),
    (MCC:	542;	COUNTRY:	'Fiji';									            	LATITUDINE:		-18.1333;			LONGITUDINE:	178.41666),
    (MCC:	244;	COUNTRY:	'Finland';								          	LATITUDINE:		60.17840;			LONGITUDINE:	24.938963),
    (MCC:	208;	COUNTRY:	'France';								            	LATITUDINE:		48.86666;			LONGITUDINE:	2.3330555),
    (MCC:	547;	COUNTRY:	'French Polynesia';				          	LATITUDINE:		-17.5333;			LONGITUDINE:	-149.5666),
    (MCC:	628;	COUNTRY:	'Gabon';									            LATITUDINE:		0.3833333;		LONGITUDINE:	9.45),
    (MCC:	282;	COUNTRY:	'Georgia';								          	LATITUDINE:		41.71666;			LONGITUDINE:	44.783333),
    (MCC:	262;	COUNTRY:	'Germany';								          	LATITUDINE:		52.53376;			LONGITUDINE:	13.411561),
    (MCC:	620;	COUNTRY:	'Ghana';							  	          	LATITUDINE:		5.55;	  			LONGITUDINE:	-0.2166666),
    (MCC:	266;	COUNTRY:	'Gibraltar';							          	LATITUDINE:		36.13774;			LONGITUDINE:	-4.654625),
    (MCC:	202;	COUNTRY:	'Greece';							  	          	LATITUDINE:		37.97911;			LONGITUDINE:	23.716736),
    (MCC:	290;	COUNTRY:	'Greenland';							          	LATITUDINE:		64.18333;			LONGITUDINE:	-51.75),
    (MCC:	704;	COUNTRY:	'Guatemala';							          	LATITUDINE:		14.61666;			LONGITUDINE:	-90.51666),
    (MCC:	611;	COUNTRY:	'Guinea';								            	LATITUDINE:		9.55;			  	LONGITUDINE:	-13.7),
    (MCC:	632;	COUNTRY:	'Guinea-Bissau';				 	          	LATITUDINE:		11.85;				LONGITUDINE:	-15.58333),
    (MCC:	738;	COUNTRY:	'Guyana';								            	LATITUDINE:		6.8;			  	LONGITUDINE:	-58.16666),
    (MCC:	372;	COUNTRY:	'Haiti';								            	LATITUDINE:		18.53333;			LONGITUDINE:	-72.33333),
    (MCC:	708;	COUNTRY:	'Honduras';								          	LATITUDINE:		14.1;			  	LONGITUDINE:	-87.21666),
    (MCC:	454;	COUNTRY:	'Hong Kong';							          	LATITUDINE:		22.25;				LONGITUDINE:	114.16666),
    (MCC:	216;	COUNTRY:	'Hungary';								          	LATITUDINE:		47.50375;			LONGITUDINE:	19.040680),
    (MCC:	274;	COUNTRY:	'Iceland';								          	LATITUDINE:		64.13534;			LONGITUDINE:	-20.10493),
    (MCC:	404;	COUNTRY:	'India';								             	LATITUDINE:		28.6;		   		LONGITUDINE:	77.2),
    (MCC:	405;	COUNTRY:	'India';								             	LATITUDINE:		28.6;		   		LONGITUDINE:	77.2),
    (MCC:	510;	COUNTRY:	'Indonesia';							          	LATITUDINE:		-6.16666;			LONGITUDINE:	106.81666),
    (MCC:	432;	COUNTRY:	'Iran';									             	LATITUDINE:		35.66666;			LONGITUDINE:	51.416666),
    (MCC:	418;	COUNTRY:	'Iraq';									             	LATITUDINE:		33.33333;			LONGITUDINE:	44.383333),
    (MCC:	272;	COUNTRY:	'Ireland';								          	LATITUDINE:		53.34665;			LONGITUDINE:	-5.995277),
    (MCC:	425;	COUNTRY:	'Israel';								             	LATITUDINE:		31.76666;			LONGITUDINE:	35.233333),
    (MCC:	222;	COUNTRY:	'Italy';								             	LATITUDINE:		41.89305;			LONGITUDINE:	12.483333),
    (MCC:	441;	COUNTRY:	'Japan';								             	LATITUDINE:		35.68333;			LONGITUDINE:	139.75),
    (MCC:	440;	COUNTRY:	'Japan';								             	LATITUDINE:		35.68333;			LONGITUDINE:	139.75),
    (MCC:	416;	COUNTRY:	'Jordan';								             	LATITUDINE:		31.95;				LONGITUDINE:	35.933333),
    (MCC:	639;	COUNTRY:	'Kenya';								             	LATITUDINE:		-1.28333;			LONGITUDINE:	36.816666),
    (MCC:	545;	COUNTRY:	'Kiribati';								          	LATITUDINE:		1.316666;			LONGITUDINE:	172.96666),
    (MCC:	419;	COUNTRY:	'Kuwait';								            	LATITUDINE:		29.36666;			LONGITUDINE:	47.966666),
    (MCC:	437;	COUNTRY:	'Kyrgyzstan';							          	LATITUDINE:		42.86666;			LONGITUDINE:	74.6),
    (MCC:	247;	COUNTRY:	'Latvia';								            	LATITUDINE:		56.95545;			LONGITUDINE:	24.105377),
    (MCC:	415;	COUNTRY:	'Lebanon';								          	LATITUDINE:		33.86666;			LONGITUDINE:	35.5),
    (MCC:	651;	COUNTRY:	'Lesotho';								          	LATITUDINE:		-29.3166;			LONGITUDINE:	27.483333),
    (MCC:	618;	COUNTRY:	'Liberia';								          	LATITUDINE:		6.3;		  		LONGITUDINE:	-10.8),
    (MCC:	606;	COUNTRY:	'Libya';							  	          	LATITUDINE:		32.88333;			LONGITUDINE:	13.166666),
    (MCC:	295;	COUNTRY:	'Liechtenstein';					          	LATITUDINE:		47.14396;			LONGITUDINE:	9.5213694),
    (MCC:	246;	COUNTRY:	'Lithuania';							          	LATITUDINE:		54.69923;			LONGITUDINE:	25.279541),
    (MCC:	270;	COUNTRY:	'Luxembourg';							          	LATITUDINE:		49.61026;			LONGITUDINE:	6.1293416),
    (MCC:	455;	COUNTRY:	'Macao';								            	LATITUDINE:		22.16666;			LONGITUDINE:	113.55),
    (MCC:	646;	COUNTRY:	'Madagascar';							          	LATITUDINE:		-18.9166;			LONGITUDINE:	47.516666),
    (MCC:	650;	COUNTRY:	'Malawi';								            	LATITUDINE:		-13.9833;			LONGITUDINE:	33.783333),
    (MCC:	502;	COUNTRY:	'Malaysia';								          	LATITUDINE:		3.166666;			LONGITUDINE:	101.7),
    (MCC:	472;	COUNTRY:	'Maldives';								          	LATITUDINE:		4.166666;			LONGITUDINE:	73.5),
    (MCC:	610;	COUNTRY:	'Mali';									            	LATITUDINE:		12.65;				LONGITUDINE:	-8),
    (MCC:	278;	COUNTRY:	'Malta';								            	LATITUDINE:		35.90458;			LONGITUDINE:	14.518905),
    (MCC:	340;	COUNTRY:	'Martinique';							          	LATITUDINE:		14.6;		  		LONGITUDINE:	-61.08305),
    (MCC:	609;	COUNTRY:	'Mauritania';							          	LATITUDINE:		18.11666;			LONGITUDINE:	-16.03333),
    (MCC:	617;	COUNTRY:	'Mauritius';							          	LATITUDINE:		-20.15;				LONGITUDINE:	57.483333),
    (MCC:	334;	COUNTRY:	'Mexico';								            	LATITUDINE:		19.43333;			LONGITUDINE:	-99.13333),
    (MCC:	550;	COUNTRY:	'Micronesia. Federated States';				LATITUDINE:		6.916666;			LONGITUDINE:	158.15),
    (MCC:	259;	COUNTRY:	'Moldova';								           	LATITUDINE:		47.01490;			LONGITUDINE:	28.849411),
    (MCC:	212;	COUNTRY:	'Monaco';								             	LATITUDINE:		43.74028;			LONGITUDINE:	7.4255777),
    (MCC:	428;	COUNTRY:	'Mongolia';								           	LATITUDINE:		47.91666;			LONGITUDINE:	106.91666),
    (MCC:	297;	COUNTRY:	'Montenegro';							           	LATITUDINE:		42.45235;			LONGITUDINE:	19.260013),
    (MCC:	604;	COUNTRY:	'Morocco';								           	LATITUDINE:		27.15361;			LONGITUDINE:	-13.20305),
    (MCC:	643;	COUNTRY:	'Mozambique';							           	LATITUDINE:		-25.95;				LONGITUDINE:	32.583333),
    (MCC:	414;	COUNTRY:	'Myanmar';								           	LATITUDINE:		16.8;			  	LONGITUDINE:	96.15),
    (MCC:	649;	COUNTRY:	'Namibia';								           	LATITUDINE:		-22.5666;			LONGITUDINE:	17.083333),
    (MCC:	429;	COUNTRY:	'Nepal';								             	LATITUDINE:		27.71666;			LONGITUDINE:	85.316666),
    (MCC:	204;	COUNTRY:	'Netherlands';							         	LATITUDINE:		52.37895;			LONGITUDINE:	4.89235),
    (MCC:	546;	COUNTRY:	'New Caledonia';						         	LATITUDINE:		-22.2666;			LONGITUDINE:	166.45),
    (MCC:	548;	COUNTRY:	'New Zealand';							         	LATITUDINE:		-41.4666;			LONGITUDINE:	174.85),
    (MCC:	530;	COUNTRY:	'New Zealand';							         	LATITUDINE:		-41.4666;			LONGITUDINE:	174.85),
    (MCC:	710;	COUNTRY:	'Nicaragua';							           	LATITUDINE:		12.15;				LONGITUDINE:	-86.28333),
    (MCC:	614;	COUNTRY:	'Niger';								             	LATITUDINE:		13.51666;			LONGITUDINE:	2.1166666),
    (MCC:	621;	COUNTRY:	'Nigeria';								           	LATITUDINE:		9.083333;			LONGITUDINE:	7.5333333),
    (MCC:	555;	COUNTRY:	'Niue';									             	LATITUDINE:		-19.0166;			LONGITUDINE:	-169.9166),
    (MCC:	450;	COUNTRY:	'North Korea';					 		         	LATITUDINE:		37.55;				LONGITUDINE:	126.98333),
    (MCC:	242;	COUNTRY:	'Norway';								             	LATITUDINE:		59.91373;			LONGITUDINE:	10.738791),
    (MCC:	422;	COUNTRY:	'Oman';									             	LATITUDINE:		23.61666;			LONGITUDINE:	58.583333),
    (MCC:	410;	COUNTRY:	'Pakistan';							   	         	LATITUDINE:		33.7;			  	LONGITUDINE:	73.166666),
    (MCC:	552;	COUNTRY:	'Palau';								             	LATITUDINE:		7.483333;			LONGITUDINE:	134.63333),
    (MCC:	714;	COUNTRY:	'Panama';								             	LATITUDINE:		8.966666;			LONGITUDINE:	-79.53333),
    (MCC:	537;	COUNTRY:	'Papua New Guinea';					         	LATITUDINE:		-9.5;			  	LONGITUDINE:	147.16666),
    (MCC:	744;	COUNTRY:	'Paraguay';							  	         	LATITUDINE:		-25.2666;			LONGITUDINE:	-57.66666),
    (MCC:	460;	COUNTRY:	'People''s Republic of China';				LATITUDINE:		39.91666;			LONGITUDINE:	116.38333),
    (MCC:	716;	COUNTRY:	'Peru';									            	LATITUDINE:		-12.05;				LONGITUDINE:	-77.05),
    (MCC:	515;	COUNTRY:	'Philippines';					            	LATITUDINE:		14.58333;			LONGITUDINE:	121),
    (MCC:	260;	COUNTRY:	'Poland';								            	LATITUDINE:		52.22948;			LONGITUDINE:	21.012725),
    (MCC:	268;	COUNTRY:	'Portugal';							            	LATITUDINE:		38.71042;			LONGITUDINE:	-8.864866),
    (MCC:	427;	COUNTRY:	'Qatar';								            	LATITUDINE:		25.28333;			LONGITUDINE:	51.533333),
    (MCC:	294;	COUNTRY:	'Republic of Macedonia';    					LATITUDINE:		42.00848;			LONGITUDINE:	21.436386),
    (MCC:	629;	COUNTRY:	'Republic of the Congo';    					LATITUDINE:		4.933333;			LONGITUDINE:	-52.33333),
    (MCC:	226;	COUNTRY:	'Romania';							          		LATITUDINE:		44.44799;			LONGITUDINE:	26.098708),
    (MCC:	250;	COUNTRY:	'Russia';								            	LATITUDINE:		55.76344;			LONGITUDINE:	37.619933),
    (MCC:	635;	COUNTRY:	'Rwanda';								            	LATITUDINE:		-1.95;				LONGITUDINE:	30.066666),
    (MCC:	308;	COUNTRY:	'Saint Pierre and Miquelon';  				LATITUDINE:		46.76666;			LONGITUDINE:	-56.18333),
    (MCC:	544;	COUNTRY:	'Samoa';								             	LATITUDINE:		-13.8333;			LONGITUDINE:	-171.7333),
    (MCC:	549;	COUNTRY:	'Samoa';								             	LATITUDINE:		-13.8333;			LONGITUDINE:	-171.7333),
    (MCC:	292;	COUNTRY:	'San Marino';						          		LATITUDINE:		43.93208;			LONGITUDINE:	12.448625),
    (MCC:	420;	COUNTRY:	'Saudi Arabia';					        			LATITUDINE:		24.63333;			LONGITUDINE:	46.716666),
    (MCC:	608;	COUNTRY:	'Senegal';							          		LATITUDINE:		24.63333;			LONGITUDINE:	46.716666),
    (MCC:	220;	COUNTRY:	'Serbia';								            	LATITUDINE:		44.82860;			LONGITUDINE:	20.478516),
    (MCC:	633;	COUNTRY:	'Seychelles';						        	  	LATITUDINE:		-4.63333;			LONGITUDINE:	55.45),
    (MCC:	619;	COUNTRY:	'Sierra Leone';					        			LATITUDINE:		8.5;			  	LONGITUDINE:	-13.25),
    (MCC:	525;	COUNTRY:	'Singapore';						        	  	LATITUDINE:		1.283333;			LONGITUDINE:	103.85),
    (MCC:	231;	COUNTRY:	'Slovakia';							        	  	LATITUDINE:		48.15371;			LONGITUDINE:	17.107086),
    (MCC:	293;	COUNTRY:	'Slovenia';							        	  	LATITUDINE:		46.05417;			LONGITUDINE:	14.506072),
    (MCC:	540;	COUNTRY:	'Solomon Islands';			        			LATITUDINE:		-9.43333;			LONGITUDINE:	159.95),
    (MCC:	637;	COUNTRY:	'Somalia';							        	  	LATITUDINE:		2.066666;			LONGITUDINE:	45.366666),
    (MCC:	655;	COUNTRY:	'South Africa';					        			LATITUDINE:		-25.7;				LONGITUDINE:	28.216666),
    (MCC:	467;	COUNTRY:	'South Korea';					        			LATITUDINE:		39.01666;			LONGITUDINE:	125.75),
    (MCC:	659;	COUNTRY:	'South Sudan (Republic of)';			  	LATITUDINE:		15.6;		  		LONGITUDINE:	32.533333),
    (MCC:	214;	COUNTRY:	'Spain';							           	  	LATITUDINE:		40.42290;			LONGITUDINE:	-2.296922),
    (MCC:	413;	COUNTRY:	'Sri Lanka';					           			LATITUDINE:		6.933333;			LONGITUDINE:	79.85),
    (MCC:	634;	COUNTRY:	'Sudan';							           	  	LATITUDINE:		15.6;			  	LONGITUDINE:	32.533333),
    (MCC:	746;	COUNTRY:	'Suriname';						           			LATITUDINE:		5.833333;			LONGITUDINE:	-55.16666),
    (MCC:	240;	COUNTRY:	'Sweden';							           	  	LATITUDINE:		59.33493;			LONGITUDINE:	18.064613),
    (MCC:	228;	COUNTRY:	'Switzerland';				           			LATITUDINE:		46.94944;			LONGITUDINE:	7.4482138),
    (MCC:	417;	COUNTRY:	'Syria';							           	  	LATITUDINE:		33.5;			  	LONGITUDINE:	36.3),
    (MCC:	466;	COUNTRY:	'Taiwan';							           	  	LATITUDINE:		25.05;				LONGITUDINE:	121.5),
    (MCC:	436;	COUNTRY:	'Tajikistan';					           			LATITUDINE:		38.58333;			LONGITUDINE:	68.8),
    (MCC:	640;	COUNTRY:	'Tanzania';						           			LATITUDINE:		-6.8;			  	LONGITUDINE:	39.283333),
    (MCC:	520;	COUNTRY:	'Thailand';						           			LATITUDINE:		13.75;				LONGITUDINE:	100.51666),
    (MCC:	607;	COUNTRY:	'The Gambia';					           			LATITUDINE:		13.45;				LONGITUDINE:	-16.56666),
    (MCC:	615;	COUNTRY:	'Togo';								           	  	LATITUDINE:		6.133333;			LONGITUDINE:	1.2166666),
    (MCC:	539;	COUNTRY:	'Tonga';							           	  	LATITUDINE:		-21.1333;			LONGITUDINE:	-175.2),
    (MCC:	605;	COUNTRY:	'Tunisia';						           			LATITUDINE:		36.8;			  	LONGITUDINE:	10.183333),
    (MCC:	286;	COUNTRY:	'Turkey';							            		LATITUDINE:		39.94386;			LONGITUDINE:	32.856030),
    (MCC:	438;	COUNTRY:	'Turkmenistan';				           			LATITUDINE:		37.95;				LONGITUDINE:	58.383333),
    (MCC:	553;	COUNTRY:	'Tuvalu';							           	   	LATITUDINE:		-8.5;			  	LONGITUDINE:	179.2),
    (MCC:	641;	COUNTRY:	'Uganda';							           	   	LATITUDINE:		0.3166666;		LONGITUDINE:	32.416666),
    (MCC:	255;	COUNTRY:	'Ukraine';						           	 		LATITUDINE:		50.45371;			LONGITUDINE:	30.503830),
    (MCC:	424;	COUNTRY:	'United Arab Emirates';          	 		LATITUDINE:		24.46666;			LONGITUDINE:	54.366666),
    (MCC:	430;	COUNTRY:	'United Arab Emirates';          	 		LATITUDINE:		24.46666;			LONGITUDINE:	54.366666),
    (MCC:	431;	COUNTRY:	'United Arab Emirates';          	 		LATITUDINE:		24.46666;			LONGITUDINE:	54.366666),
    (MCC:	235;	COUNTRY:	'United Kingdom';			           	 		LATITUDINE:		51.51045;			LONGITUDINE:	0.12634166),
    (MCC:	234;	COUNTRY:	'United Kingdom';			           	 		LATITUDINE:		51.51045;			LONGITUDINE:	0.12634166),
    (MCC:	311;	COUNTRY:	'United States Minor Outlying ';			LATITUDINE:		16.75;				LONGITUDINE:	-169.5166),
    (MCC:	312;	COUNTRY:	'United States Minor Outlying ';			LATITUDINE:		16.75;				LONGITUDINE:	-169.5166),
    (MCC:	316;	COUNTRY:	'United States Minor Outlying ';			LATITUDINE:		16.75;				LONGITUDINE:	-169.5166),
    (MCC:	310;	COUNTRY:	'United States Minor Outlying ';			LATITUDINE:		16.75;				LONGITUDINE:	-169.5166),
    (MCC:	748;	COUNTRY:	'Uruguay';								          	LATITUDINE:		-34.8833;			LONGITUDINE:	-56.18333),
    (MCC:	434;	COUNTRY:	'Uzbekistan';							          	LATITUDINE:		41.33333;			LONGITUDINE:	69.3),
    (MCC:	541;	COUNTRY:	'Vanuatu';								          	LATITUDINE:		-17.7333;			LONGITUDINE:	168.31666),
    (MCC:	734;	COUNTRY:	'Venezuela';							          	LATITUDINE:		10.5;			  	LONGITUDINE:	-66.93333),
    (MCC:	452;	COUNTRY:	'Vietnam';								          	LATITUDINE:		21.03333;			LONGITUDINE:	105.85),
    (MCC:	421;	COUNTRY:	'Yemen';							             		LATITUDINE:		15.35;				LONGITUDINE:	44.2),
    (MCC:	645;	COUNTRY:	'Zambia';							             		LATITUDINE:		-15.4166;			LONGITUDINE:	28.283333),
    (MCC:	648;	COUNTRY:	'Zimbabwe';						          			LATITUDINE:		-17.8333;			LONGITUDINE:	31.05)
);

function MCCToCountry(const aMCC:integer):String;
function MCCToCoordinate(const aMCC:integer ;var aCoordinate: TMapCoordinate):Boolean;

implementation


function MCCToCountry(const aMCC:integer):String;
var LMccRow : TMCCRow;
  
begin
  Result := 'Unknown';
  if aMCC < MIN_MCC then exit;  
  for LMccRow in MCC_ROWS do
  begin
    if LMccRow.MCC = aMCC then
    begin
      Result := LMccRow.Country;
      Break;
    end;
  end;
end;


function MCCToCoordinate(const aMCC:integer ;var aCoordinate: TMapCoordinate):Boolean;
var LMccRow : TMCCRow; 
begin
  result := False;  
  for LMccRow in MCC_ROWS do
  begin
    if LMccRow.MCC = aMCC then
    begin
      result := True;
      
      aCoordinate.Latitude  := LMccRow.LATITUDINE;
      aCoordinate.Longitude := LMccRow.LONGITUDINE;      
      aCoordinate.Info      := LMccRow.COUNTRY;            
      aCoordinate.DateTime  := 0;
      Break;
    end;
  end;
end;

end.
