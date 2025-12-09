"""
Test suite for KSI-AFR-04 AST-based vulnerability detection.

Validates AST-first analysis for Python, C#, and Java across vulnerability patterns:
- Insecure deserialization (pickle, BinaryFormatter, ObjectInputStream)
- SQL injection (string concatenation in queries)
- XXE (XML External Entity) vulnerabilities
- YAML unsafe loading

Progress: 12/17 analyzers @ 70.6% (AFR-04 completes milestone)
"""

import sys
from pathlib import Path

# Add src to path for imports
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.ksi.ksi_afr_04 import KSI_AFR_04_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_pickle_insecure_deserialization():
    """Test Python pickle detection (insecure deserialization - CWE-502)."""
    code = """
import pickle

def load_data(file_path):
    with open(file_path, 'rb') as f:
        data = pickle.load(f)  # Vulnerable: can execute arbitrary code
    return data
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "python", "test.py")
    
    print(f"DEBUG: Found {result.total_issues} issues")
    for f in result.findings:
        print(f"  - {f.title}: {f.description[:100]}")
    
    assert result.total_issues == 1, f"Expected 1 issue, got {result.total_issues}"
    assert result.findings[0].severity == Severity.HIGH
    assert "pickle" in result.findings[0].title.lower()
    assert "CWE-502" in result.findings[0].description
    print("[PASS] Python pickle detection works")


def test_python_safe_json_passes():
    """Test Python safe JSON serialization passes."""
    code = """
import json

def load_data(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)  # Safe: JSON doesn't execute code
    return data
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "python", "test.py")
    
    assert result.total_issues == 0
    print("[PASS] Python safe JSON passes")


def test_python_yaml_unsafe_load():
    """Test Python yaml.load() detection (insecure deserialization)."""
    code = """
import yaml

def load_config(file_path):
    with open(file_path, 'r') as f:
        config = yaml.load(f)  # Vulnerable: can execute code
    return config
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "python", "config.py")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.HIGH
    assert "yaml" in result.findings[0].title.lower()
    assert "CWE-502" in result.findings[0].description
    print("[PASS] Python yaml.load() detection works")


def test_python_yaml_safe_load_passes():
    """Test Python yaml.safe_load() passes."""
    code = """
import yaml

def load_config(file_path):
    with open(file_path, 'r') as f:
        config = yaml.safe_load(f)  # Safe: no code execution
    return config
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "python", "config.py")
    
    assert result.total_issues == 0
    print("[PASS] Python yaml.safe_load() passes")


def test_python_sql_injection():
    """Test Python SQL injection detection (CWE-89)."""
    code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable: SQL injection via string concatenation
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "python", "db.py")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert "SQL" in result.findings[0].title
    assert "CWE-89" in result.findings[0].description
    print("[PASS] Python SQL injection detection works")


def test_python_parameterized_query_passes():
    """Test Python parameterized query passes."""
    code = """
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "python", "db.py")
    
    assert result.total_issues == 0
    print("[PASS] Python parameterized query passes")


def test_csharp_binaryformatter_insecure():
    """Test C# BinaryFormatter detection (insecure deserialization)."""
    code = """
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class DataLoader
{
    public object LoadData(string filePath)
    {
        var formatter = new BinaryFormatter();  // Vulnerable: deprecated by Microsoft
        using var stream = File.OpenRead(filePath);
        return formatter.Deserialize(stream);  // Can execute arbitrary code
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "DataLoader.cs")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert "BinaryFormatter" in result.findings[0].title
    assert "CWE-502" in result.findings[0].description
    print("[PASS] C# BinaryFormatter detection works")


def test_csharp_json_safe_passes():
    """Test C# System.Text.Json passes."""
    code = """
using System.Text.Json;

public class DataLoader
{
    public MyData LoadData(string json)
    {
        var options = new JsonSerializerOptions 
        { 
            PropertyNameCaseInsensitive = true 
        };
        return JsonSerializer.Deserialize<MyData>(json, options);  // Safe
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "DataLoader.cs")
    
    assert result.total_issues == 0
    print("[PASS] C# System.Text.Json passes")


def test_csharp_sql_injection():
    """Test C# SQL injection detection via string interpolation."""
    code = """
using System.Data.SqlClient;

public class UserRepository
{
    public User GetUser(int userId)
    {
        using var conn = new SqlConnection(connectionString);
        // Vulnerable: SQL injection via string interpolation
        var cmd = new SqlCommand($"SELECT * FROM Users WHERE Id = {userId}", conn);
        conn.Open();
        using var reader = cmd.ExecuteReader();
        return MapUser(reader);
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "UserRepository.cs")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert "SQL" in result.findings[0].title
    assert "CWE-89" in result.findings[0].description
    print("[PASS] C# SQL injection detection works")


def test_csharp_parameterized_query_passes():
    """Test C# parameterized query passes."""
    code = """
using System.Data.SqlClient;

public class UserRepository
{
    public User GetUser(int userId)
    {
        using var conn = new SqlConnection(connectionString);
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @userId", conn);
        cmd.Parameters.AddWithValue("@userId", userId);  // Safe: parameterized
        conn.Open();
        using var reader = cmd.ExecuteReader();
        return MapUser(reader);
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "UserRepository.cs")
    
    assert result.total_issues == 0
    print("[PASS] C# parameterized query passes")


def test_csharp_xxe_vulnerability():
    """Test C# XXE detection (XML External Entity)."""
    code = """
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xml)
    {
        var doc = new XmlDocument();  // Vulnerable: no secure settings
        doc.LoadXml(xml);  // Can process external entities
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "XmlParser.cs")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.HIGH
    assert "XXE" in result.findings[0].title
    assert "CWE-611" in result.findings[0].description
    print("[PASS] C# XXE detection works")


def test_java_objectinputstream_insecure():
    """Test Java ObjectInputStream detection (insecure deserialization)."""
    code = """
import java.io.*;

public class DataLoader {
    public Object loadData(String filePath) throws IOException, ClassNotFoundException {
        FileInputStream fis = new FileInputStream(filePath);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object data = ois.readObject();  // Vulnerable: can execute arbitrary code
        ois.close();
        return data;
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "java", "DataLoader.java")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert "ObjectInputStream" in result.findings[0].title
    assert "CWE-502" in result.findings[0].description
    print("[PASS] Java ObjectInputStream detection works")


def test_java_jackson_safe_passes():
    """Test Java Jackson JSON serialization passes."""
    code = """
import com.fasterxml.jackson.databind.ObjectMapper;

public class DataLoader {
    public MyData loadData(String json) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, MyData.class);  // Safe: JSON deserialization
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "java", "DataLoader.java")
    
    assert result.total_issues == 0
    print("[PASS] Java Jackson passes")


def test_java_sql_injection():
    """Test Java SQL injection detection via string concatenation."""
    code = """
import java.sql.*;

public class UserRepository {
    public User getUser(int userId) throws SQLException {
        Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement();
        // Vulnerable: SQL injection via concatenation
        String sql = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(sql);
        return mapUser(rs);
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "java", "UserRepository.java")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert "SQL" in result.findings[0].title
    assert "CWE-89" in result.findings[0].description
    print("[PASS] Java SQL injection detection works")


def test_java_prepared_statement_passes():
    """Test Java PreparedStatement passes."""
    code = """
import java.sql.*;

public class UserRepository {
    public User getUser(int userId) throws SQLException {
        Connection conn = DriverManager.getConnection(url);
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setInt(1, userId);  // Safe: parameterized query
        ResultSet rs = pstmt.executeQuery();
        return mapUser(rs);
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "java", "UserRepository.java")
    
    assert result.total_issues == 0
    print("[PASS] Java PreparedStatement passes")


def test_java_xxe_vulnerability():
    """Test Java XXE detection (XML External Entity)."""
    code = """
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class XmlParser {
    public void parseXml(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Vulnerable: no secure features set
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(xml);
    }
}
"""
    
    analyzer = KSI_AFR_04_Analyzer()
    result = analyzer.analyze(code, "java", "XmlParser.java")
    
    assert result.total_issues == 1
    assert result.findings[0].severity == Severity.HIGH
    assert "XXE" in result.findings[0].title
    assert "CWE-611" in result.findings[0].description
    print("[PASS] Java XXE detection works")


if __name__ == "__main__":
    print("\n" + "="*70)
    print("KSI-AFR-04: Vulnerability Detection and Response - AST Conversion Tests")
    print("="*70 + "\n")
    
    # Python tests (6 tests)
    print("Python Tests:")
    test_python_pickle_insecure_deserialization()
    test_python_safe_json_passes()
    test_python_yaml_unsafe_load()
    test_python_yaml_safe_load_passes()
    test_python_sql_injection()
    test_python_parameterized_query_passes()
    
    # C# tests (6 tests)
    print("\nC# Tests:")
    test_csharp_binaryformatter_insecure()
    test_csharp_json_safe_passes()
    test_csharp_sql_injection()
    test_csharp_parameterized_query_passes()
    test_csharp_xxe_vulnerability()
    
    # Java tests (6 tests)
    print("\nJava Tests:")
    test_java_objectinputstream_insecure()
    test_java_jackson_safe_passes()
    test_java_sql_injection()
    test_java_prepared_statement_passes()
    test_java_xxe_vulnerability()
    
    print("\n" + "="*70)
    print("ALL 17 AFR-04 TESTS PASSED [PASS]")
    print("Progress: 12/17 analyzers complete (70.6%)")
    print("="*70)
